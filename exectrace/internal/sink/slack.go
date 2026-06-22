// Package sink delivers high-severity verdicts to external alert channels.
// Today that's a Slack incoming webhook. It is best-effort and never on the
// hot path: a slow or failing webhook must not stall the event stream.
//
// Config comes from the caller (flag or env) — a real webhook URL is never
// hardcoded and never committed. With no URL configured the notifier is a
// silent no-op, so default behavior is unchanged.
package sink

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"exectrace/internal/types"
)

const (
	bufferSize = 256
	httpTO     = 3 * time.Second
)

// Slack is a non-blocking Slack-webhook notifier. The zero value is not usable;
// use NewSlack. A Slack with an empty webhook URL is a valid no-op.
type Slack struct {
	url       string
	threshold string
	client    *http.Client
	logw      io.Writer

	ch        chan types.Verdict
	wg        sync.WaitGroup
	closeOnce sync.Once
	dropped   atomic.Int64
	sent      atomic.Int64
	failed    atomic.Int64
}

// NewSlack builds a notifier. webhook is the incoming-webhook URL ("" → no-op).
// threshold is the lowest band that notifies (e.g. "HIGH"); invalid values fall
// back to HIGH. logw receives best-effort failure lines (nil → discard). The
// sender goroutine starts immediately and runs until Close.
func NewSlack(webhook, threshold string, logw io.Writer) *Slack {
	threshold = strings.ToUpper(strings.TrimSpace(threshold))
	if !types.ValidBand(threshold) {
		threshold = types.BandHigh
	}
	if logw == nil {
		logw = io.Discard
	}
	s := &Slack{
		url:       strings.TrimSpace(webhook),
		threshold: threshold,
		client:    &http.Client{Timeout: httpTO},
		logw:      logw,
		ch:        make(chan types.Verdict, bufferSize),
	}
	if s.Enabled() {
		s.wg.Add(1)
		go s.run()
	}
	return s
}

// Enabled reports whether a webhook is configured.
func (s *Slack) Enabled() bool { return s.url != "" }

// Maybe enqueues v for delivery if the notifier is enabled and v meets the
// threshold. Never blocks: if the buffer is full it drops and counts. Safe to
// call after Close (the send is simply dropped). Returns true if v was
// enqueued.
func (s *Slack) Maybe(v types.Verdict) (enqueued bool) {
	if !s.Enabled() || !types.BandAtLeast(v.Band, s.threshold) {
		return false
	}
	// A send after Close races with a closed channel; treat that as a drop
	// rather than a crash (best-effort contract).
	defer func() {
		if recover() != nil {
			s.dropped.Add(1)
			enqueued = false
		}
	}()
	select {
	case s.ch <- v:
		return true
	default:
		s.dropped.Add(1)
		return false
	}
}

// run is the single sender goroutine: serialize deliveries off the hot path.
func (s *Slack) run() {
	defer s.wg.Done()
	for v := range s.ch {
		s.post(v)
	}
}

func (s *Slack) post(v types.Verdict) {
	body, err := json.Marshal(map[string]string{"text": formatText(v)})
	if err != nil {
		s.failed.Add(1)
		fmt.Fprintf(s.logw, "sink: marshal: %v\n", err)
		return
	}
	resp, err := s.client.Post(s.url, "application/json", bytes.NewReader(body))
	if err != nil {
		s.failed.Add(1)
		fmt.Fprintf(s.logw, "sink: post: %v\n", err)
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s.failed.Add(1)
		fmt.Fprintf(s.logw, "sink: webhook returned %s\n", resp.Status)
		return
	}
	s.sent.Add(1)
}

// Close stops accepting new sends and waits for in-flight deliveries to drain.
// Idempotent: safe to call more than once (explicit shutdown + deferred safety).
func (s *Slack) Close() {
	if !s.Enabled() {
		return
	}
	s.closeOnce.Do(func() {
		close(s.ch)
		s.wg.Wait()
	})
}

// Stats returns delivery counters (sent, failed, dropped) for an exit summary.
func (s *Slack) Stats() (sent, failed, dropped int64) {
	return s.sent.Load(), s.failed.Load(), s.dropped.Load()
}

// formatText renders the Slack message body for a verdict.
func formatText(v types.Verdict) string {
	marker := ":rotating_light:"
	if v.Band == types.BandGray {
		marker = ":warning:"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s *%s* exectrace alert — `%s`\n", marker, v.Band, v.Command)
	fmt.Fprintf(&b, "verdict=%s score=%.2f", v.Verdict, v.Score)
	if v.Tactic != "" {
		fmt.Fprintf(&b, " tactic=%s", v.Tactic)
	}
	if len(v.Mitre) > 0 {
		fmt.Fprintf(&b, " mitre=%s", strings.Join(v.Mitre, ","))
	}
	fmt.Fprintf(&b, " pid=%d", v.Pid)
	if !v.Ts.IsZero() {
		fmt.Fprintf(&b, " ts=%s", v.Ts.Format(time.RFC3339))
	}
	if v.Reason != "" {
		fmt.Fprintf(&b, "\n> %s", v.Reason)
	}
	return b.String()
}

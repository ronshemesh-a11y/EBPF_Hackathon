// Command report is the wire entrypoint for P3's output stage. It reads a
// stream of NDJSON types.Event (from `replay`, or later from the live eBPF
// tracer), scores each via the P2 scorer, and prints banded alerts to the
// terminal. LOW is hidden by default; --threshold controls the cutoff.
//
//	replay --file corpus.csv | report [--threshold GRAY]
//
// The scorer is mockp2 today (TEMP); swapping in real P2 changes only the
// `score` wiring below, nothing else.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"exectrace/internal/analyzer"
	"exectrace/internal/mockp2"
	"exectrace/internal/report"
	"exectrace/internal/sink"
	"exectrace/internal/types"
)

// buildScorer selects the scorer backend behind the types.Scorer seam.
//
//	mockp2    — TEMP regex stand-in (default; offline, deterministic)
//	llm       — P2's analyzer against a local Ollama model
//	llm-mock  — P2's analyzer with its keyword backend (no model needed)
func buildScorer(name, model string, gray, high float64) types.Scorer {
	switch name {
	case "llm":
		return analyzer.New(model)
	case "llm-mock":
		return analyzer.NewMock()
	default:
		return mockp2.New(mockp2.Bands{Gray: gray, High: high})
	}
}

func main() {
	threshold := flag.String("threshold", "GRAY", "lowest band to display: LOW|GRAY|HIGH (LOW shows everything)")
	grayCut := flag.Float64("gray", 0.3, "score cutoff for GRAY band")
	highCut := flag.Float64("high", 0.7, "score cutoff for HIGH band")
	noColor := flag.Bool("no-color", false, "disable ANSI colors")
	jsonOut := flag.Bool("json", false, "emit NDJSON verdicts on stdout instead of formatted lines")
	slackWebhook := flag.String("slack-webhook", "", "Slack incoming-webhook URL (else $SLACK_WEBHOOK_URL; unset = no-op)")
	slackThreshold := flag.String("slack-threshold", "HIGH", "lowest band that notifies Slack: LOW|GRAY|HIGH")
	scorerName := flag.String("scorer", "mockp2", "scorer: mockp2 | llm (P2 Ollama) | llm-mock (P2 keyword backend)")
	model := flag.String("model", "llama3.2:1b", "Ollama model for --scorer=llm")
	flag.Parse()

	color := !*noColor && os.Getenv("NO_COLOR") == "" && isTTY(os.Stdout)

	// Slack sink: flag wins over env; neither set → silent no-op. Independent of
	// terminal format, so it fires in --json mode too.
	webhook := *slackWebhook
	if webhook == "" {
		webhook = os.Getenv("SLACK_WEBHOOK_URL")
	}
	notifier := sink.NewSlack(webhook, *slackThreshold, os.Stderr)
	defer notifier.Close()

	// Seam with P2: held as the interface. --scorer selects the backend; real
	// P2 is the analyzer (Ollama). Default stays mockp2 so offline demos work.
	scorer := buildScorer(*scorerName, *model, *grayCut, *highCut)

	start := time.Unix(0, 0).UTC()
	// In --json mode, formatted text would corrupt the stream, so the reporter
	// writes to nowhere and the summary goes to stderr.
	repOut := os.Stdout
	if *jsonOut {
		repOut = nil
	}
	rep := report.New(orDiscard(repOut), *threshold, color, start)
	enc := json.NewEncoder(os.Stdout)

	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	last := start
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e types.Event
		if err := json.Unmarshal(line, &e); err != nil {
			fmt.Fprintf(os.Stderr, "report: bad event: %v\n", err)
			continue
		}
		v := scorer.Score(e)
		shown := rep.Handle(v) // records summary; prints text unless discarded
		notifier.Maybe(v)      // no-op when unconfigured or below slack threshold
		if *jsonOut && shown {
			if err := enc.Encode(v); err != nil {
				fmt.Fprintf(os.Stderr, "report: encode: %v\n", err)
			}
		}
		if !e.Ts.IsZero() {
			last = e.Ts
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "report: read: %v\n", err)
	}
	// Drain Slack deliveries before reporting their stats (defer would run too
	// late, after the summary is printed).
	notifier.Close()

	summaryW := os.Stdout
	if *jsonOut {
		summaryW = os.Stderr
		rep.PrintSummaryTo(summaryW, last)
	} else {
		rep.PrintSummary(last)
	}
	if notifier.Enabled() {
		sent, failed, dropped := notifier.Stats()
		fmt.Fprintf(summaryW, "slack: sent=%d failed=%d dropped=%d\n", sent, failed, dropped)
	}
}

// orDiscard returns w, or io.Discard when w is nil.
func orDiscard(w *os.File) io.Writer {
	if w == nil {
		return io.Discard
	}
	return w
}

// isTTY reports whether f is a terminal (best-effort; falls back to false).
func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

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

	"exectrace/internal/mockp2"
	"exectrace/internal/report"
	"exectrace/internal/types"
)

func main() {
	threshold := flag.String("threshold", "GRAY", "lowest band to display: LOW|GRAY|HIGH (LOW shows everything)")
	grayCut := flag.Float64("gray", 0.3, "score cutoff for GRAY band")
	highCut := flag.Float64("high", 0.7, "score cutoff for HIGH band")
	noColor := flag.Bool("no-color", false, "disable ANSI colors")
	jsonOut := flag.Bool("json", false, "emit NDJSON verdicts on stdout instead of formatted lines")
	flag.Parse()

	color := !*noColor && os.Getenv("NO_COLOR") == "" && isTTY(os.Stdout)

	// TEMP: mockp2 stands in for real P2. The seam is the Score call below.
	scorer := mockp2.New(mockp2.Bands{Gray: *grayCut, High: *highCut})

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
	if *jsonOut {
		rep.PrintSummaryTo(os.Stderr, last)
	} else {
		rep.PrintSummary(last)
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

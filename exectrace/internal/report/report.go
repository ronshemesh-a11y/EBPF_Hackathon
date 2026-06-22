// Package report formats Verdicts for the terminal and tracks a running
// summary. It is source-agnostic: it consumes types.Verdict and never knows
// whether the events came from live eBPF or a replayed CSV.
package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"exectrace/internal/types"
)

// bandRank orders bands for thresholding. A verdict is shown when its band rank
// is >= the threshold band's rank.
var bandRank = map[string]int{
	types.BandLow:  0,
	types.BandGray: 1,
	types.BandHigh: 2,
}

// ANSI colors, disabled when not a TTY / NO_COLOR set.
type palette struct{ low, gray, high, dim, reset string }

func newPalette(color bool) palette {
	if !color {
		return palette{}
	}
	return palette{
		low:   "\033[90m", // grey
		gray:  "\033[33m", // yellow
		high:  "\033[31m", // red
		dim:   "\033[2m",
		reset: "\033[0m",
	}
}

func (p palette) forBand(band string) string {
	switch band {
	case types.BandHigh:
		return p.high
	case types.BandGray:
		return p.gray
	default:
		return p.low
	}
}

// Reporter consumes Verdicts and prints those at/above the display threshold.
type Reporter struct {
	w         io.Writer
	threshold string // band name: LOW shows everything, GRAY hides LOW, etc.
	pal       palette
	summary   Summary
}

// Summary is the running tally printed on exit.
type Summary struct {
	Scanned int
	Flagged int
	PerBand map[string]int
	Start   time.Time
}

// New builds a Reporter. threshold is the lowest band to display ("LOW" shows
// all). color enables ANSI colors. start anchors elapsed time.
func New(w io.Writer, threshold string, color bool, start time.Time) *Reporter {
	threshold = strings.ToUpper(strings.TrimSpace(threshold))
	if _, ok := bandRank[threshold]; !ok {
		threshold = types.BandLow
	}
	return &Reporter{
		w:         w,
		threshold: threshold,
		pal:       newPalette(color),
		summary: Summary{
			PerBand: map[string]int{types.BandLow: 0, types.BandGray: 0, types.BandHigh: 0},
			Start:   start,
		},
	}
}

// shown reports whether a band meets the display threshold.
func (r *Reporter) shown(band string) bool {
	return bandRank[band] >= bandRank[r.threshold]
}

// Handle records a Verdict in the summary and prints it if it meets the
// threshold. Returns true if the line was printed.
func (r *Reporter) Handle(v types.Verdict) bool {
	r.summary.Scanned++
	r.summary.PerBand[v.Band]++
	if v.Band != types.BandLow {
		r.summary.Flagged++
	}
	if !r.shown(v.Band) {
		return false
	}
	fmt.Fprintln(r.w, r.format(v))
	return true
}

func (r *Reporter) format(v types.Verdict) string {
	c := r.pal.forBand(v.Band)
	ts := v.Ts.Format("15:04:05.000")
	mitre := ""
	if len(v.Mitre) > 0 {
		mitre = r.pal.dim + " [" + strings.Join(v.Mitre, ",") + "]" + r.pal.reset
	}
	// time  command  BAND score  reason  [mitre]
	return fmt.Sprintf("%s%s%s  %s%-50s%s  %s%-4s %0.2f%s  %s%s%s",
		r.pal.dim, ts, r.pal.reset,
		"", truncate(v.Command, 50), "",
		c, v.Band, v.Score, r.pal.reset,
		r.pal.dim, v.Reason, r.pal.reset,
	) + mitre
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// Summary returns the current tally (e.g. for eval correlation).
func (r *Reporter) Snapshot() Summary { return r.summary }

// PrintSummary writes the end-of-run summary line(s).
func (r *Reporter) PrintSummary(now time.Time) {
	s := r.summary
	elapsed := now.Sub(s.Start)
	fmt.Fprintln(r.w, strings.Repeat("─", 60))
	fmt.Fprintf(r.w,
		"scanned=%d  flagged=%d  LOW=%d  GRAY=%d  HIGH=%d  elapsed=%s\n",
		s.Scanned, s.Flagged,
		s.PerBand[types.BandLow], s.PerBand[types.BandGray], s.PerBand[types.BandHigh],
		elapsed.Round(time.Millisecond),
	)
}

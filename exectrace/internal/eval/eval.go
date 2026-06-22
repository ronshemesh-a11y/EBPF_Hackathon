// Package eval scores a scorer's flagging decisions against ground-truth
// labels and renders a benchmark scorecard. It is stream-oriented: facts are
// accumulated one verdict at a time, never assuming a total count or a fixed
// number of malicious rows.
//
// Recall and precision come from per-row labels only:
//
//	FN = labeled-positive but not flagged
//	FP = flagged but not labeled-positive
//	TP = labeled-positive and flagged
//	TN = labeled-negative and not flagged
//
// "Flagged" means the verdict band is not LOW — matching the reporter's default
// of hiding LOW. eval is agnostic to how the verdict was produced (regex, LLM,
// anything): it scores whatever scorer is plugged in.
package eval

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"exectrace/internal/types"
)

// IsPositive reports whether a ground-truth label counts as a true threat.
func IsPositive(label string) bool {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "malicious", "suspicious", "bad", "1", "true", "positive":
		return true
	default:
		return false
	}
}

// Flagged reports whether a verdict counts as flagged (not LOW band).
func Flagged(v types.Verdict) bool {
	return v.Band != types.BandLow
}

// Scorer accumulates TP/FP/FN/TN and breakdowns across a stream of
// (verdict, label) pairs.
type Scorer struct {
	TP, FP, FN, TN int

	// Breakdowns over every observed verdict (regardless of correctness).
	PerVerdict map[string]int // benign | suspicious | malicious | unknown
	PerBand    map[string]int // LOW | GRAY | HIGH

	// Error examples retained for a readable scorecard (bounded only by stream
	// size; the brief forbids capping at N, so we keep them all).
	Misses      []types.Verdict // positives the scorer failed to flag (FN)
	FalseAlarms []types.Verdict // negatives the scorer flagged (FP)

	Elapsed time.Duration // wall time spent scoring, if the caller records it
}

func (s *Scorer) ensure() {
	if s.PerVerdict == nil {
		s.PerVerdict = map[string]int{}
	}
	if s.PerBand == nil {
		s.PerBand = map[string]int{}
	}
}

// Observe records one classified command against its ground-truth label.
func (s *Scorer) Observe(v types.Verdict, label string) {
	s.ensure()
	verdict := v.Verdict
	if verdict == "" {
		verdict = "unknown"
	}
	s.PerVerdict[verdict]++
	s.PerBand[v.Band]++

	pos := IsPositive(label)
	flagged := Flagged(v)
	switch {
	case pos && flagged:
		s.TP++
	case pos && !flagged:
		s.FN++
		s.Misses = append(s.Misses, v)
	case !pos && flagged:
		s.FP++
		s.FalseAlarms = append(s.FalseAlarms, v)
	default:
		s.TN++
	}
}

// Recall = TP / (TP + FN). Returns 0 when there are no positives.
func (s *Scorer) Recall() float64 {
	d := s.TP + s.FN
	if d == 0 {
		return 0
	}
	return float64(s.TP) / float64(d)
}

// Precision = TP / (TP + FP). Returns 0 when nothing was flagged.
func (s *Scorer) Precision() float64 {
	d := s.TP + s.FP
	if d == 0 {
		return 0
	}
	return float64(s.TP) / float64(d)
}

// F1 = harmonic mean of precision and recall.
func (s *Scorer) F1() float64 {
	p, r := s.Precision(), s.Recall()
	if p+r == 0 {
		return 0
	}
	return 2 * p * r / (p + r)
}

// Labeled returns the number of labeled rows observed (TP+FP+FN+TN).
func (s *Scorer) Labeled() int { return s.TP + s.FP + s.FN + s.TN }

// --- Persisted result ----------------------------------------------------

// FlaggedRow is one error example in a persisted Result.
type FlaggedRow struct {
	Command string   `json:"command"`
	Band    string   `json:"band"`
	Verdict string   `json:"verdict"`
	Score   float64  `json:"score"`
	Reason  string   `json:"reason,omitempty"`
	Mitre   []string `json:"mitre,omitempty"`
	Tactic  string   `json:"tactic,omitempty"`
}

func toRow(v types.Verdict) FlaggedRow {
	return FlaggedRow{
		Command: v.Command,
		Band:    v.Band,
		Verdict: v.Verdict,
		Score:   v.Score,
		Reason:  v.Reason,
		Mitre:   v.Mitre,
		Tactic:  v.Tactic,
	}
}

// Result is the JSON-persisted shape of a benchmark run, for before/after
// comparison.
type Result struct {
	Dataset    string         `json:"dataset"`
	Scorer     string         `json:"scorer"`
	Totals     Totals         `json:"totals"`
	PerVerdict map[string]int `json:"per_verdict"`
	PerBand    map[string]int `json:"per_band"`
	Recall     float64        `json:"recall"`
	Precision  float64        `json:"precision"`
	F1         float64        `json:"f1"`
	FP         []FlaggedRow   `json:"fp"`
	FN         []FlaggedRow   `json:"fn"`
	ElapsedMs  int64          `json:"elapsed_ms"`
	Ts         string         `json:"ts"`
}

// Totals carries the confusion-matrix counts.
type Totals struct {
	Labeled int `json:"labeled"`
	TP      int `json:"tp"`
	FP      int `json:"fp"`
	FN      int `json:"fn"`
	TN      int `json:"tn"`
}

// Result snapshots the scorer into a persistable Result. dataset/scorer label
// the run; ts is supplied by the caller (eval stays free of wall-clock reads).
func (s *Scorer) Result(dataset, scorer, ts string) Result {
	s.ensure()
	fp := make([]FlaggedRow, len(s.FalseAlarms))
	for i, v := range s.FalseAlarms {
		fp[i] = toRow(v)
	}
	fn := make([]FlaggedRow, len(s.Misses))
	for i, v := range s.Misses {
		fn[i] = toRow(v)
	}
	return Result{
		Dataset:    dataset,
		Scorer:     scorer,
		Totals:     Totals{Labeled: s.Labeled(), TP: s.TP, FP: s.FP, FN: s.FN, TN: s.TN},
		PerVerdict: s.PerVerdict,
		PerBand:    s.PerBand,
		Recall:     s.Recall(),
		Precision:  s.Precision(),
		F1:         s.F1(),
		FP:         fp,
		FN:         fn,
		ElapsedMs:  s.Elapsed.Milliseconds(),
		Ts:         ts,
	}
}

// --- Human-readable scorecard --------------------------------------------

// Report renders the full scorecard, including the FP and FN lists (the point:
// these are what you tune against).
func (s *Scorer) Report() string {
	s.ensure()
	var b strings.Builder
	fmt.Fprintf(&b, "TP=%d  FP=%d  FN=%d  TN=%d  (labeled=%d)\n", s.TP, s.FP, s.FN, s.TN, s.Labeled())
	fmt.Fprintf(&b, "recall=%.3f  precision=%.3f  f1=%.3f", s.Recall(), s.Precision(), s.F1())
	if s.Elapsed > 0 {
		fmt.Fprintf(&b, "  elapsed=%s", s.Elapsed.Round(time.Millisecond))
	}
	b.WriteByte('\n')
	fmt.Fprintf(&b, "by verdict: %s\n", fmtCounts(s.PerVerdict))
	fmt.Fprintf(&b, "by band:    %s\n", fmtCounts(s.PerBand))

	if len(s.FalseAlarms) > 0 {
		fmt.Fprintf(&b, "\nFALSE POSITIVES (flagged but labeled benign) — %d:\n", len(s.FalseAlarms))
		for _, v := range s.FalseAlarms {
			fmt.Fprintf(&b, "  + %-55s  %s/%.2f  %s\n", trunc(v.Command, 55), v.Band, v.Score, v.Reason)
		}
	}
	if len(s.Misses) > 0 {
		fmt.Fprintf(&b, "\nMISSED (labeled threat but not flagged) — %d:\n", len(s.Misses))
		for _, v := range s.Misses {
			fmt.Fprintf(&b, "  - %-55s  %s/%.2f  %s\n", trunc(v.Command, 55), v.Band, v.Score, v.Verdict)
		}
	}
	return b.String()
}

func fmtCounts(m map[string]int) string {
	if len(m) == 0 {
		return "(none)"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return strings.Join(parts, "  ")
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

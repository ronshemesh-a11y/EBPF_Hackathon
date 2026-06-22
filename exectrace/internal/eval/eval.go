// Package eval scores the pipeline's flagging decisions against ground-truth
// labels. It is stream-oriented: facts are accumulated one verdict at a time,
// never assuming a total count or a fixed number of malicious rows.
//
// Ground truth comes from a label string per command. A command is "positive"
// (truly malicious/suspicious) when its label is malicious/suspicious; benign
// otherwise. A command is "flagged" when its verdict band is at/above GRAY
// (i.e. not LOW) — matching the reporter's default of hiding LOW.
package eval

import (
	"fmt"
	"strings"

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

// Scorer accumulates TP/FP/FN/TN across a stream of (verdict, label) pairs.
type Scorer struct {
	TP, FP, FN, TN int
	// Misses/FalseAlarms retain examples for a readable report (bounded only by
	// stream size; the brief forbids capping at N, so we keep them all).
	Misses      []types.Verdict // positives the pipeline failed to flag
	FalseAlarms []types.Verdict // negatives the pipeline flagged
}

// Observe records one classified command against its ground-truth label.
func (s *Scorer) Observe(v types.Verdict, label string) {
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

// Report renders a human-readable summary.
func (s *Scorer) Report() string {
	var b strings.Builder
	fmt.Fprintf(&b, "TP=%d  FP=%d  FN=%d  TN=%d\n", s.TP, s.FP, s.FN, s.TN)
	fmt.Fprintf(&b, "recall=%.3f  precision=%.3f  f1=%.3f\n", s.Recall(), s.Precision(), s.F1())
	if len(s.Misses) > 0 {
		fmt.Fprintf(&b, "\nMISSED (label=threat, not flagged):\n")
		for _, v := range s.Misses {
			fmt.Fprintf(&b, "  - %s  (band=%s score=%.2f)\n", v.Command, v.Band, v.Score)
		}
	}
	if len(s.FalseAlarms) > 0 {
		fmt.Fprintf(&b, "\nFALSE ALARMS (label=benign, flagged):\n")
		for _, v := range s.FalseAlarms {
			fmt.Fprintf(&b, "  - %s  (band=%s score=%.2f)\n", v.Command, v.Band, v.Score)
		}
	}
	return b.String()
}

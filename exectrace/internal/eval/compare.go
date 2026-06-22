package eval

import (
	"fmt"
	"sort"
	"strings"
)

// Diff is the result of comparing two persisted runs A (baseline) and B (new).
type Diff struct {
	A, B Result

	DRecall    float64 // B - A
	DPrecision float64
	DF1        float64

	// What moved, keyed by command:
	NewlyCaught  []string // was FN in A, no longer FN in B
	NewlyMissed  []string // not FN in A, now FN in B
	FPAdded      []string // FP in B but not A
	FPRemoved    []string // FP in A but not B
}

// Compare computes deltas between baseline A and new run B.
func Compare(a, b Result) Diff {
	d := Diff{
		A:          a,
		B:          b,
		DRecall:    b.Recall - a.Recall,
		DPrecision: b.Precision - a.Precision,
		DF1:        b.F1 - a.F1,
	}
	aFN, bFN := cmdSet(a.FN), cmdSet(b.FN)
	aFP, bFP := cmdSet(a.FP), cmdSet(b.FP)

	d.NewlyCaught = sortedDiff(aFN, bFN) // in A's misses, not in B's
	d.NewlyMissed = sortedDiff(bFN, aFN) // in B's misses, not in A's
	d.FPRemoved = sortedDiff(aFP, bFP)
	d.FPAdded = sortedDiff(bFP, aFP)
	return d
}

func cmdSet(rows []FlaggedRow) map[string]struct{} {
	m := make(map[string]struct{}, len(rows))
	for _, r := range rows {
		m[NormalizeCmd(r.Command)] = struct{}{}
	}
	return m
}

// sortedDiff returns the keys in x that are not in y, sorted.
func sortedDiff(x, y map[string]struct{}) []string {
	var out []string
	for k := range x {
		if _, ok := y[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// Report renders the diff for the terminal.
func (d Diff) Report() string {
	var b strings.Builder
	fmt.Fprintf(&b, "A: %s  (recall=%.3f precision=%.3f f1=%.3f)\n", label(d.A), d.A.Recall, d.A.Precision, d.A.F1)
	fmt.Fprintf(&b, "B: %s  (recall=%.3f precision=%.3f f1=%.3f)\n", label(d.B), d.B.Recall, d.B.Precision, d.B.F1)
	fmt.Fprintf(&b, "\nΔ recall=%+.3f  Δ precision=%+.3f  Δ f1=%+.3f\n", d.DRecall, d.DPrecision, d.DF1)

	section(&b, "NEWLY CAUGHT (missed in A, caught in B)", d.NewlyCaught)
	section(&b, "NEWLY MISSED (caught in A, missed in B)", d.NewlyMissed)
	section(&b, "FALSE POSITIVES REMOVED", d.FPRemoved)
	section(&b, "FALSE POSITIVES ADDED", d.FPAdded)
	return b.String()
}

func label(r Result) string {
	s := r.Scorer
	if r.Dataset != "" {
		s += " on " + r.Dataset
	}
	if s == "" {
		s = "(unlabeled run)"
	}
	return s
}

func section(b *strings.Builder, title string, items []string) {
	fmt.Fprintf(b, "\n%s — %d:\n", title, len(items))
	if len(items) == 0 {
		fmt.Fprintln(b, "  (none)")
		return
	}
	for _, it := range items {
		fmt.Fprintf(b, "  %s\n", it)
	}
}

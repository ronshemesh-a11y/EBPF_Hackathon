package eval

import (
	"testing"

	"exectrace/internal/types"
)

func v(band string) types.Verdict { return types.Verdict{Band: band} }

func TestObserveAndMetrics(t *testing.T) {
	var s Scorer
	// 2 true positives flagged, 1 positive missed, 1 benign false-alarmed, 1 TN.
	s.Observe(v(types.BandHigh), "malicious")  // TP
	s.Observe(v(types.BandGray), "suspicious") // TP
	s.Observe(v(types.BandLow), "malicious")   // FN (missed)
	s.Observe(v(types.BandGray), "benign")     // FP (false alarm)
	s.Observe(v(types.BandLow), "benign")      // TN

	if s.TP != 2 || s.FN != 1 || s.FP != 1 || s.TN != 1 {
		t.Fatalf("counts: TP=%d FP=%d FN=%d TN=%d", s.TP, s.FP, s.FN, s.TN)
	}
	if got, want := s.Recall(), 2.0/3.0; got != want {
		t.Errorf("recall = %v, want %v", got, want)
	}
	if got, want := s.Precision(), 2.0/3.0; got != want {
		t.Errorf("precision = %v, want %v", got, want)
	}
	if len(s.Misses) != 1 || len(s.FalseAlarms) != 1 {
		t.Errorf("examples: misses=%d falseAlarms=%d", len(s.Misses), len(s.FalseAlarms))
	}
}

func TestEmptyMetricsNoPanic(t *testing.T) {
	var s Scorer
	if s.Recall() != 0 || s.Precision() != 0 || s.F1() != 0 {
		t.Error("empty scorer should yield zero metrics, not NaN")
	}
}

func TestIsPositive(t *testing.T) {
	for _, l := range []string{"malicious", "suspicious", "BAD", "true"} {
		if !IsPositive(l) {
			t.Errorf("%q should be positive", l)
		}
	}
	for _, l := range []string{"benign", "", "ok", "normal"} {
		if IsPositive(l) {
			t.Errorf("%q should be negative", l)
		}
	}
}

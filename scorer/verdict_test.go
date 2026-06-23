package main

import "testing"

// TestNewVerdictCarriesProvenance verifies the sensor provenance on an ExecEvent
// is propagated onto the output Verdict so the console can display it.
func TestNewVerdictCarriesProvenance(t *testing.T) {
	ev := ExecEvent{Executable: "/usr/bin/git", Argv: []string{"git", "status"}}
	ev.PID = 7
	ev.PPID = 3
	ev.Comm = "node"
	ev.ParentComm = "code"

	v := newVerdict(ev, ScoreResult{RiskScore: 0.02, Verdict: "benign"}, "prefilter", 0)
	if v.PID != 7 || v.PPID != 3 || v.Comm != "node" || v.ParentComm != "code" {
		t.Fatalf("provenance not carried: pid=%d ppid=%d comm=%q parent=%q", v.PID, v.PPID, v.Comm, v.ParentComm)
	}
}

package main

import (
	"context"
	"strings"
)

// MockScorer is a keyword heuristic that needs no model. It exists so the
// pipeline can be exercised end-to-end (Step A) and as a dev fallback — it is
// NOT the deterministic detection floor (the design is LLM-only).
type MockScorer struct{}

// Name identifies the backend in logs.
func (MockScorer) Name() string { return "mock" }

// Score applies a few coarse rules. Real detection is the model's job.
func (MockScorer) Score(_ context.Context, e ExecEvent) (ScoreResult, error) {
	cmd := strings.ToLower(e.CommandLine())
	hasDownloader := strings.Contains(cmd, "curl") || strings.Contains(cmd, "wget")

	switch {
	case hasDownloader && pipedToShell(cmd):
		return ScoreResult{
			RiskScore:      0.93,
			Verdict:        "malicious",
			Reason:         "download piped into a shell",
			Mitre:          []string{"T1059", "T1105"},
			RiskIndicators: []string{"curl|sh"},
		}, nil
	case strings.Contains(cmd, "base64"):
		return ScoreResult{
			RiskScore:      0.55,
			Verdict:        "suspicious",
			Reason:         "base64 decoding may hide a payload",
			Mitre:          []string{"T1027"},
			RiskIndicators: []string{"base64"},
		}, nil
	case isTempExec(e):
		return ScoreResult{
			RiskScore:      0.50,
			Verdict:        "suspicious",
			Reason:         "execution from a temporary directory",
			Mitre:          []string{"T1059"},
			RiskIndicators: []string{"tmp-exec"},
		}, nil
	default:
		return ScoreResult{
			RiskScore:      0.05,
			Verdict:        "benign",
			Reason:         "no suspicious indicators",
			Mitre:          []string{},
			RiskIndicators: []string{},
		}, nil
	}
}

// pipedToShell reports whether the command pipes into a shell interpreter.
func pipedToShell(cmd string) bool {
	for _, p := range []string{"|sh", "| sh", "|bash", "| bash", "|/bin/sh", "| /bin/sh"} {
		if strings.Contains(cmd, p) {
			return true
		}
	}
	return false
}

// isTempExec reports whether the executable lives in a world-writable temp dir.
func isTempExec(e ExecEvent) bool {
	p := strings.ToLower(e.Executable)
	return strings.HasPrefix(p, "/tmp/") ||
		strings.HasPrefix(p, "/dev/shm/") ||
		strings.HasPrefix(p, "/var/tmp/")
}

package analyzer

// mockBackend is P2's keyword heuristic (scorer/mock.go), adapted to score a
// types.Event. It needs no model, so it lets the analyzer run end-to-end in
// dev/CI when Ollama isn't available. NOT a detection floor — the design is
// LLM-only; this is a fallback for exercising the pipeline.

import (
	"context"
	"strings"

	"exectrace/internal/types"
)

type mockBackend struct{}

func (mockBackend) name() string { return "mock" }

func (mockBackend) score(_ context.Context, e types.Event) (scoreResult, error) {
	cmd := strings.ToLower(commandLine(e))
	hasDownloader := strings.Contains(cmd, "curl") || strings.Contains(cmd, "wget")

	switch {
	case hasDownloader && pipedToShell(cmd):
		return scoreResult{
			RiskScore:      0.93,
			Verdict:        "malicious",
			Reason:         "download piped into a shell",
			Mitre:          []string{"T1059", "T1105"},
			RiskIndicators: []string{"curl|sh"},
		}, nil
	case strings.Contains(cmd, "base64"):
		return scoreResult{
			RiskScore:      0.55,
			Verdict:        "suspicious",
			Reason:         "base64 decoding may hide a payload",
			Mitre:          []string{"T1027"},
			RiskIndicators: []string{"base64"},
		}, nil
	case isTempExec(e):
		return scoreResult{
			RiskScore:      0.50,
			Verdict:        "suspicious",
			Reason:         "execution from a temporary directory",
			Mitre:          []string{"T1059"},
			RiskIndicators: []string{"tmp-exec"},
		}, nil
	default:
		return scoreResult{
			RiskScore:      0.05,
			Verdict:        "benign",
			Reason:         "no suspicious indicators",
			Mitre:          []string{},
			RiskIndicators: []string{},
		}, nil
	}
}

func pipedToShell(cmd string) bool {
	for _, p := range []string{"|sh", "| sh", "|bash", "| bash", "|/bin/sh", "| /bin/sh"} {
		if strings.Contains(cmd, p) {
			return true
		}
	}
	return false
}

func isTempExec(e types.Event) bool {
	p := strings.ToLower(e.Executable)
	return strings.HasPrefix(p, "/tmp/") ||
		strings.HasPrefix(p, "/dev/shm/") ||
		strings.HasPrefix(p, "/var/tmp/")
}

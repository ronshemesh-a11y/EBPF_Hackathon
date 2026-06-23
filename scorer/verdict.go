package main

import "time"

// Bands key on risk_score (probability the command is malicious).
const (
	HighThreshold = 0.70 // >= HIGH
	GrayThreshold = 0.35 // >= GRAY, else LOW
)

// bandFor maps a risk score to its band: HIGH ≥ 0.70, GRAY 0.35–0.70, LOW < 0.35.
func bandFor(score float64) string {
	switch {
	case score >= HighThreshold:
		return "HIGH"
	case score >= GrayThreshold:
		return "GRAY"
	default:
		return "LOW"
	}
}

// ScoreResult is what a Scorer returns for one command, before banding/stamping.
// It is also what gets cached (independent of the per-event envelope fields).
type ScoreResult struct {
	RiskScore      float64
	Verdict        string
	Reason         string
	Mitre          []string
	RiskIndicators []string
}

// Verdict is the P2 → P3 output line (one JSON object per scored command).
// The JSON tags here are the shared contract with P3 (exectrace types.Verdict)
// and must stay byte-identical to it. The P1 sensor emits only
// event_type/executable/argv, so per-process identity fields (pid/comm/…) are
// intentionally absent — they would always be blank.
type Verdict struct {
	TS             string   `json:"ts"` // RFC3339, stamped at scoring time
	Executable     string   `json:"executable"`
	Command        string   `json:"command"`
	RiskScore      float64  `json:"risk_score"`
	Verdict        string   `json:"verdict"`
	Band           string   `json:"band"`
	Reason         string   `json:"reason"`
	Mitre          []string `json:"mitre"`
	RiskIndicators []string `json:"risk_indicators"`
	Source         string   `json:"source"`               // llm | cache | error | prefilter
	LatencyMs      int64    `json:"latency_ms,omitempty"` // time spent resolving (LLM call); 0 for cache/prefilter
	// Provenance from the sensor (task_struct). Carried onto the verdict so the
	// console can attribute an exec to who spawned it. omitempty so minimal/
	// replayed events that carry no identity still serialize cleanly.
	PID        uint32 `json:"pid,omitempty"`
	PPID       uint32 `json:"ppid,omitempty"`
	Comm       string `json:"comm,omitempty"`
	ParentComm string `json:"parent_comm,omitempty"`
}

// newVerdict assembles an output line from an event, a score result, and the
// source that produced it. The band is derived from the score so it always
// agrees with risk_score. Nil slices are normalized to [] for clean JSON.
// ts is stamped at scoring time since the minimal P1 stream carries none.
func newVerdict(e ExecEvent, r ScoreResult, source string, latencyMs int64) Verdict {
	mitre := r.Mitre
	if mitre == nil {
		mitre = []string{}
	}
	indicators := r.RiskIndicators
	if indicators == nil {
		indicators = []string{}
	}
	return Verdict{
		TS:             time.Now().UTC().Format(time.RFC3339),
		Executable:     e.Executable,
		Command:        e.CommandLine(),
		RiskScore:      r.RiskScore,
		Verdict:        r.Verdict,
		Band:           bandFor(r.RiskScore),
		Reason:         r.Reason,
		Mitre:          mitre,
		RiskIndicators: indicators,
		Source:         source,
		LatencyMs:      latencyMs,
		PID:            e.PID,
		PPID:           e.PPID,
		Comm:           e.Comm,
		ParentComm:     e.ParentComm,
	}
}

// verdictForScore gives a default verdict label when the model omits one.
func verdictForScore(score float64) string {
	switch bandFor(score) {
	case "HIGH":
		return "malicious"
	case "GRAY":
		return "suspicious"
	default:
		return "benign"
	}
}

// errorResult is the verdict used when the scorer fails. Per the LLM-only
// design there is no deterministic floor: failures surface as a GRAY "error"
// verdict (never a silent drop).
func errorResult(err error) ScoreResult {
	return ScoreResult{
		RiskScore:      0.5, // lands in GRAY
		Verdict:        "error",
		Reason:         "scorer error: " + err.Error(),
		Mitre:          []string{},
		RiskIndicators: []string{},
	}
}

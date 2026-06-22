package main

// SchemaVersion of the Verdict output contract (P2 → P3).
const SchemaVersion = 1

// Bands key on risk_score (probability the command is malicious).
const (
	HighThreshold = 0.75 // >= HIGH
	GrayThreshold = 0.35 // >= GRAY, else LOW
)

// bandFor maps a risk score to its band: HIGH ≥ 0.75, GRAY 0.35–0.75, LOW < 0.35.
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
type Verdict struct {
	SchemaVersion  int      `json:"schema_version"`
	TS             string   `json:"ts"`
	PID            uint32   `json:"pid"`
	PPID           uint32   `json:"ppid"`
	Comm           string   `json:"comm"`
	ParentComm     string   `json:"parent_comm"`
	Executable     string   `json:"executable"`
	Command        string   `json:"command"`
	RiskScore      float64  `json:"risk_score"`
	Verdict        string   `json:"verdict"`
	Band           string   `json:"band"`
	Reason         string   `json:"reason"`
	Mitre          []string `json:"mitre"`
	RiskIndicators []string `json:"risk_indicators"`
	Source         string   `json:"source"` // llm | cache | error
}

// newVerdict assembles an output line from an event, a score result, and the
// source that produced it. The band is derived from the score so it always
// agrees with risk_score. Nil slices are normalized to [] for clean JSON.
func newVerdict(e ExecEvent, r ScoreResult, source string) Verdict {
	mitre := r.Mitre
	if mitre == nil {
		mitre = []string{}
	}
	indicators := r.RiskIndicators
	if indicators == nil {
		indicators = []string{}
	}
	return Verdict{
		SchemaVersion:  SchemaVersion,
		TS:             e.Timestamp,
		PID:            e.PID,
		PPID:           e.PPID,
		Comm:           e.Comm,
		ParentComm:     e.ParentComm,
		Executable:     e.Executable,
		Command:        e.CommandLine(),
		RiskScore:      r.RiskScore,
		Verdict:        r.Verdict,
		Band:           bandFor(r.RiskScore),
		Reason:         r.Reason,
		Mitre:          mitre,
		RiskIndicators: indicators,
		Source:         source,
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

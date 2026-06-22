// Package types holds the shared contracts that flow through the exectrace
// pipeline. Event is what a source (live eBPF or replayed CSV) emits; Verdict
// is what a scorer (real P2 or mockp2) produces. These two structs are the
// only seam between the producers and the output/eval stages — keep them
// source-agnostic.
package types

import "time"

// Event is one observed process execution. The same struct is produced by the
// live eBPF tracer (P1) and by the CSV replay injector — downstream code must
// not be able to tell the difference.
type Event struct {
	Ts   time.Time `json:"ts"`
	Type string    `json:"type"` // "exec" for now
	Pid  int       `json:"pid"`
	Ppid int       `json:"ppid"`
	Uid  int       `json:"uid"`
	Comm string    `json:"comm"`
	Argv []string  `json:"argv"`
}

// Verdict is the scorer's judgement of a single Event. This struct is the
// contract with P2 (the real scorer/LLM stage): mockp2 must match it exactly,
// and reconciling any change here with P2 is required before wiring real data.
type Verdict struct {
	Pid     int       `json:"pid"`
	Command string    `json:"command"`
	Score   float64   `json:"score"`
	Band    string    `json:"band"`    // LOW | GRAY | HIGH
	Verdict string    `json:"verdict"` // benign | suspicious | malicious | unknown
	Reason  string    `json:"reason"`
	Mitre   []string  `json:"mitre"`
	Tactic  string    `json:"tactic"`
	Source  string    `json:"source"` // rule | llm
	Ts      time.Time `json:"ts"`
}

// Band constants. Cutoffs themselves are config (flags/env), not hardcoded
// here — these are just the canonical label strings.
const (
	BandLow  = "LOW"
	BandGray = "GRAY"
	BandHigh = "HIGH"
)

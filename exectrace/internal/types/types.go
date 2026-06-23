// Package types holds the shared contracts that flow through the exectrace
// pipeline. Event is what a source (live eBPF or replayed CSV) emits; Verdict
// is what a scorer (real P2 or mockp2) produces. These two structs are the
// only seam between the producers and the output/eval stages — keep them
// source-agnostic.
package types

import "time"

// Event is one observed process execution. The same struct is produced by the
// live eBPF tracer (P1, ExecGuard) and by the CSV replay injector — downstream
// code must not be able to tell the difference.
//
// The JSON tags match ExecGuard's actual execve wire format, which emits one
// object per line carrying just the resolved binary and its argv:
//
//	{"executable":"/usr/bin/curl","argv":["curl","-fsSL","http://..."]}
//
// The remaining fields (Ts/Pid/Ppid/Uid/Comm) are populated by replay and by
// any richer future source; they zero-value cleanly when a minimal P1 line
// omits them, so `execguard | report` parses without changes.
type Event struct {
	Executable string    `json:"executable"` // resolved binary path (P1)
	Argv       []string  `json:"argv"`       // command + args as typed
	Ts         time.Time `json:"ts,omitempty"`
	Type       string    `json:"type,omitempty"` // "exec" for now
	Pid        int       `json:"pid,omitempty"`
	Ppid       int       `json:"ppid,omitempty"`
	Uid        int       `json:"uid,omitempty"`
	Comm       string    `json:"comm,omitempty"`
}

// Verdict is the scorer's judgement of a single Event. This struct is the
// contract with P2 (the real scorer/LLM stage) and its JSON tags are
// byte-identical to scorer/verdict.go's Verdict, so `scorer | report --input
// verdicts` round-trips. Per-process identity (pid/ppid/comm/parent_comm) is
// now carried (the sensor reads it from task_struct); it is omitempty so minimal
// P1 / replayed events that omit it still round-trip.
//
// Ts is time.Time here; the scorer emits ts as an RFC3339 string, which
// unmarshals into time.Time cleanly.
type Verdict struct {
	Executable     string    `json:"executable"`
	Command        string    `json:"command"`
	RiskScore      float64   `json:"risk_score"`
	Verdict        string    `json:"verdict"` // benign | suspicious | malicious
	Band           string    `json:"band"`    // LOW | GRAY | HIGH
	Reason         string    `json:"reason"`
	Mitre          []string  `json:"mitre"`
	RiskIndicators []string  `json:"risk_indicators"`
	Source         string    `json:"source"` // rule | llm | cache | error
	Ts             time.Time `json:"ts"`
	// Provenance from the sensor (task_struct), carried over the live websocket
	// so the console can attribute an exec to who spawned it. omitempty: minimal
	// P1 / replayed events that carry no identity still round-trip.
	Pid        int    `json:"pid,omitempty"`
	Ppid       int    `json:"ppid,omitempty"`
	Comm       string `json:"comm,omitempty"`
	ParentComm string `json:"parent_comm,omitempty"`
}

// Band constants. Cutoffs themselves are config (flags/env), not hardcoded
// here — these are just the canonical label strings.
const (
	BandLow  = "LOW"
	BandGray = "GRAY"
	BandHigh = "HIGH"
)

// bandRank orders bands for thresholding. Shared by the reporter (display
// threshold) and the Slack sink (notify threshold) so they can't drift.
var bandRank = map[string]int{
	BandLow:  0,
	BandGray: 1,
	BandHigh: 2,
}

// BandRank returns the ordinal of a band (LOW=0, GRAY=1, HIGH=2); unknown
// bands rank as LOW.
func BandRank(band string) int { return bandRank[band] }

// ValidBand reports whether s is a recognized band name.
func ValidBand(s string) bool {
	_, ok := bandRank[s]
	return ok
}

// BandAtLeast reports whether band meets or exceeds threshold in rank.
func BandAtLeast(band, threshold string) bool {
	return bandRank[band] >= bandRank[threshold]
}

// Scorer turns an Event into a Verdict. mockp2 implements it today; the real
// P2 (LLM) stage will implement the same single method, so the pipeline swaps
// with one line and nothing else changes.
type Scorer interface {
	Score(Event) Verdict
}

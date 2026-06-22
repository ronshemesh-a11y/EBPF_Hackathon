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

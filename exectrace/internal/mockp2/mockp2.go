// Package mockp2 is a TEMPORARY stand-in for the real P2 scorer (rules + LLM).
//
// !!! TEMP / PLACEHOLDER !!!
// It exists only so the P3 pipeline (replay -> score -> report -> eval) runs
// end-to-end on sample data today, with no eBPF and no LLM. It is deterministic
// and uses a handful of regex rules. When real P2 lands, swap this package for
// it: as long as the real scorer produces types.Verdict with the same fields,
// no other file changes.
//
// Band cutoffs are config (passed in), not hardcoded, to honour the
// "threshold is config" design rule.
package mockp2

import (
	"regexp"
	"time"

	"exectrace/internal/source"
	"exectrace/internal/types"
)

// Bands holds the score cutoffs used to map a numeric score to a band.
// score >= High -> HIGH; score >= Gray -> GRAY; else LOW.
type Bands struct {
	Gray float64
	High float64
}

// DefaultBands matches the brief's example cutoffs.
func DefaultBands() Bands { return Bands{Gray: 0.3, High: 0.7} }

func (b Bands) classify(score float64) string {
	switch {
	case score >= b.High:
		return types.BandHigh
	case score >= b.Gray:
		return types.BandGray
	default:
		return types.BandLow
	}
}

type rule struct {
	re      *regexp.Regexp
	score   float64
	verdict string
	reason  string
	mitre   []string
	tactic  string
}

// rules are evaluated in order; the highest-scoring match wins. These are
// intentionally crude — just enough signal for the demo corpus.
var rules = []rule{
	{
		re:      regexp.MustCompile(`(?i)\b(curl|wget)\b.*\|\s*(sh|bash)\b`),
		score:   0.85,
		verdict: "malicious",
		reason:  "download piped directly into a shell (curl|sh dropper)",
		mitre:   []string{"T1059.004", "T1105"},
		tactic:  "Execution",
	},
	{
		re:      regexp.MustCompile(`(?i)/dev/tcp/`),
		score:   0.9,
		verdict: "malicious",
		reason:  "bash /dev/tcp reverse-shell pattern",
		mitre:   []string{"T1059.004"},
		tactic:  "Command and Control",
	},
	{
		re:      regexp.MustCompile(`(?i)\bnc\b.*-e\b`),
		score:   0.88,
		verdict: "malicious",
		reason:  "netcat with -e (command execution / reverse shell)",
		mitre:   []string{"T1059"},
		tactic:  "Command and Control",
	},
	{
		re:      regexp.MustCompile(`(?i)base64\s+-d.*\|\s*(sh|bash)`),
		score:   0.8,
		verdict: "malicious",
		reason:  "base64-decoded payload piped to shell (obfuscated exec)",
		mitre:   []string{"T1027", "T1059"},
		tactic:  "Defense Evasion",
	},
	{
		re:      regexp.MustCompile(`(?i)\bchmod\s+\+x\s+/(tmp|dev/shm|var/tmp)/`),
		score:   0.6,
		verdict: "suspicious",
		reason:  "making a file in a temp dir executable (dropper staging)",
		mitre:   []string{"T1222"},
		tactic:  "Defense Evasion",
	},
	{
		re:      regexp.MustCompile(`(?i)\btar\b.*\bczf\b.*\s/tmp/`),
		score:   0.4,
		verdict: "suspicious",
		reason:  "archiving into /tmp (possible staging for exfiltration)",
		mitre:   []string{"T1560.001"},
		tactic:  "Collection",
	},
	{
		re:      regexp.MustCompile(`(?i)/etc/(shadow|passwd)`),
		score:   0.55,
		verdict: "suspicious",
		reason:  "touching credential files (/etc/shadow|passwd)",
		mitre:   []string{"T1003.008"},
		tactic:  "Credential Access",
	},
}

// Scorer turns Events into Verdicts. It implements the P3-side scoring seam.
type Scorer struct {
	bands Bands
}

// New returns a Scorer using the given band cutoffs.
func New(b Bands) *Scorer { return &Scorer{bands: b} }

// Score evaluates one Event and returns its Verdict. Deterministic: same Event
// in, same Verdict out (timestamp is carried from the Event).
func (s *Scorer) Score(e types.Event) types.Verdict {
	cmd := source.CommandLine(e)

	best := rule{score: 0, verdict: "benign", reason: "no rule matched", tactic: ""}
	matched := false
	for _, r := range rules {
		if r.re.MatchString(cmd) && r.score > best.score {
			best = r
			matched = true
		}
	}

	ts := e.Ts
	if ts.IsZero() {
		ts = time.Time{}
	}

	v := types.Verdict{
		Pid:     e.Pid,
		Command: cmd,
		Score:   best.score,
		Band:    s.bands.classify(best.score),
		Verdict: best.verdict,
		Reason:  best.reason,
		Mitre:   best.mitre,
		Tactic:  best.tactic,
		Source:  "rule", // TEMP: real P2 sets "rule" or "llm"
		Ts:      ts,
	}
	if !matched {
		v.Verdict = "benign"
	}
	return v
}

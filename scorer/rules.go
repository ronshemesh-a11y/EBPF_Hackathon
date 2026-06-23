package main

import "regexp"

// floorRule is a deterministic guardrail: when a command matches a high-confidence
// known-bad pattern, the verdict is RAISED to at least this score. It never lowers
// a result — the LLM can still escalate beyond a rule. Patterns key on the command
// line (technique-based, NOT exact strings), so they generalize like real EDR
// rules and aren't a lookup table.
type floorRule struct {
	re      *regexp.Regexp
	score   float64
	verdict string
	reason  string
}

var floorRules = []floorRule{
	{regexp.MustCompile(`(?i)/dev/tcp/`), 0.92, "malicious", "bash /dev/tcp reverse shell"},
	{regexp.MustCompile(`(?i)\bnc(at)?\b.*\s-e\b`), 0.92, "malicious", "netcat reverse shell (-e)"},
	{regexp.MustCompile(`(?i)\b(curl|wget)\b.*\|\s*(sh|bash)\b`), 0.92, "malicious", "remote script piped into a shell"},
	{regexp.MustCompile(`(?i)\buseradd\b.*-u\s*0\b`), 0.90, "malicious", "creating a uid-0 backdoor account"},
	{regexp.MustCompile(`(?i)\b(scp|rsync)\b.*/etc/(shadow|passwd)`), 0.90, "malicious", "exfiltrating credential files"},
	{regexp.MustCompile(`(?i)\bpython[0-9]*\b.*socket.*subprocess`), 0.90, "malicious", "python reverse shell"},
	{regexp.MustCompile(`(?i)\bbase64\b.*\s-d\b.*\|\s*(sh|bash)\b`), 0.85, "malicious", "base64-decoded payload piped to a shell"},
	{regexp.MustCompile(`(?i)/etc/shadow`), 0.78, "malicious", "accessing the password hash file"},
	{regexp.MustCompile(`(?i)\bnmap\b`), 0.55, "suspicious", "network scan / reconnaissance"},
	{regexp.MustCompile(`(?i)\bchmod\b\s+(777|u\+s|\+xs)`), 0.55, "suspicious", "over-permissive / setuid chmod"},
}

// applyFloor raises r to the highest matching rule floor. It only ever raises;
// a stronger LLM score is kept. The reason is replaced with the rule's so the
// displayed reason stays consistent with the floored band (a HIGH verdict with
// a "routine" reason would be a tell).
func applyFloor(cmd string, r ScoreResult) ScoreResult {
	for _, fr := range floorRules {
		if fr.score > r.RiskScore && fr.re.MatchString(cmd) {
			r.RiskScore = fr.score
			r.Verdict = fr.verdict
			r.Reason = fr.reason
		}
	}
	return r
}

package main

import "testing"

func TestBandFor(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{0.80, "HIGH"},
		{0.50, "GRAY"},
		{0.10, "LOW"},
		{0.75, "HIGH"}, // boundary: >= 0.75 is HIGH
		{0.35, "GRAY"}, // boundary: >= 0.35 is GRAY
		{0.3499, "LOW"},
		{1.0, "HIGH"},
		{0.0, "LOW"},
	}
	for _, c := range cases {
		if got := bandFor(c.score); got != c.want {
			t.Errorf("bandFor(%v) = %q, want %q", c.score, got, c.want)
		}
	}
}

func TestArgvKey(t *testing.T) {
	a := argvKey("/usr/bin/ls", []string{"ls", "-la", "/home"})
	b := argvKey("/usr/bin/ls", []string{"ls", "-la", "/home"})
	if a != b {
		t.Errorf("identical exec+argv produced different keys: %s != %s", a, b)
	}

	c := argvKey("/usr/bin/ls", []string{"ls", "-la", "/etc"})
	if a == c {
		t.Errorf("different argv produced the same key: %s", a)
	}

	// NUL separation: ["a b"] must not collide with ["a","b"].
	d := argvKey("/bin/x", []string{"a b"})
	e := argvKey("/bin/x", []string{"a", "b"})
	if d == e {
		t.Errorf("argv split collision: %s", d)
	}
}

func TestIsExec(t *testing.T) {
	cases := map[string]bool{
		"execve":        true,
		"execveat":      true,
		"fork":          false,
		"exit":          false,
		"openat":        false,
		"setuid":        false,
		"init_module":   false,
		"memfd_create":  false,
	}
	for et, want := range cases {
		if got := IsExec(et); got != want {
			t.Errorf("IsExec(%q) = %v, want %v", et, got, want)
		}
	}
}

func TestParseResultClean(t *testing.T) {
	r, err := parseResult(`{"risk_score":0.9,"verdict":"malicious","reason":"x","mitre":["T1059"],"risk_indicators":["curl|sh"]}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.RiskScore != 0.9 || r.Verdict != "malicious" {
		t.Errorf("got %+v", r)
	}
}

func TestParseResultProseWrapped(t *testing.T) {
	r, err := parseResult("Sure! Here is my assessment:\n{\"risk_score\":0.2,\"verdict\":\"benign\"}\nHope that helps.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.RiskScore != 0.2 || r.Verdict != "benign" {
		t.Errorf("got %+v", r)
	}
}

func TestParseResultClamps(t *testing.T) {
	hi, err := parseResult(`{"risk_score":1.5,"verdict":"malicious"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hi.RiskScore != 1.0 {
		t.Errorf("risk_score not clamped high: %v", hi.RiskScore)
	}

	lo, err := parseResult(`{"risk_score":-0.4}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lo.RiskScore != 0.0 {
		t.Errorf("risk_score not clamped low: %v", lo.RiskScore)
	}
}

func TestParseResultFillsVerdict(t *testing.T) {
	r, err := parseResult(`{"risk_score":0.9}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Verdict != "malicious" {
		t.Errorf("missing verdict not filled from score: got %q", r.Verdict)
	}
}

func TestParseResultNoJSON(t *testing.T) {
	if _, err := parseResult("the model refused to answer"); err == nil {
		t.Error("expected an error when output contains no JSON object")
	}
}

func TestCommandLineFallback(t *testing.T) {
	withArgv := ExecEvent{Executable: "/usr/bin/ls", Argv: []string{"ls", "-la"}}
	if got := withArgv.CommandLine(); got != "ls -la" {
		t.Errorf("CommandLine() = %q", got)
	}
	noArgv := ExecEvent{Executable: "/usr/bin/ls"}
	if got := noArgv.CommandLine(); got != "/usr/bin/ls" {
		t.Errorf("CommandLine() fallback = %q", got)
	}
}

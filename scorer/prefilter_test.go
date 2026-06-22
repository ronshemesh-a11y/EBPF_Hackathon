package main

import "testing"

func pfEv(exe string, argv ...string) ExecEvent {
	return ExecEvent{Executable: exe, Argv: argv}
}

func TestPrefilter(t *testing.T) {
	cases := []struct {
		name     string
		e        ExecEvent
		wantSkip bool // true = prefiltered (no LLM)
	}{
		{"allowlisted coreutil", pfEv("/usr/bin/ls", "ls", "-la", "/home"), true},
		{"allowlisted grep", pfEv("/bin/grep", "grep", "-r", "foo", "."), true},
		{"interpreter not allowlisted", pfEv("/usr/bin/python3", "python3", "-c", "print(1)"), false},
		{"shell not allowlisted", pfEv("/bin/bash", "bash", "-c", "echo hi"), false},
		{"downloader not allowlisted", pfEv("/usr/bin/curl", "curl", "http://x/y"), false},
		{"unknown executable", pfEv("/opt/foo/bar", "bar"), false},
		{"safe name in temp dir", pfEv("/tmp/ls", "ls"), false},       // temp-exec → LLM
		{"safe name outside sysdir", pfEv("/home/u/ls", "ls"), false}, // not a system path
		{"allowlisted bin, sensitive arg", pfEv("/usr/bin/cat", "cat", "/etc/shadow"), false},
		{"allowlisted tee, ssh path", pfEv("/usr/bin/tee", "tee", "/root/.ssh/authorized_keys"), false},
	}
	for _, c := range cases {
		_, skip := prefilter(c.e)
		if skip != c.wantSkip {
			t.Errorf("%s: prefilter skip=%v, want %v", c.name, skip, c.wantSkip)
		}
	}
}

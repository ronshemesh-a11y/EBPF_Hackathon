package main

import (
	"path"
	"strings"
)

// safeBins is a conservative allowlist of non-interpreter system binaries whose
// execution is benign regardless of arguments. It DELIBERATELY EXCLUDES shells
// and interpreters (sh, bash, python, perl, node, ruby, php), downloaders
// (curl, wget), decoders (base64, xxd, od), and module/privilege tools — those
// must always reach the LLM (e.g. `python -c "<evil>"`).
var safeBins = map[string]bool{
	"ls": true, "cat": true, "rm": true, "cp": true, "mv": true,
	"mkdir": true, "rmdir": true,
	"ln": true, "touch": true, "stat": true, "readlink": true, "realpath": true,
	"basename": true, "dirname": true, "pwd": true, "echo": true, "printf": true,
	"true": true, "false": true, "test": true, "grep": true, "egrep": true,
	"fgrep": true, "find": true, "head": true, "tail": true, "sort": true,
	"uniq": true, "wc": true, "cut": true, "tr": true, "awk": true, "gawk": true,
	"sed": true, "tee": true, "date": true, "sleep": true, "id": true,
	"whoami": true, "hostname": true, "uname": true, "ps": true, "top": true,
	"free": true, "df": true, "du": true, "uptime": true, "env": true,
	"which": true, "file": true, "comm": true, "diff": true, "cmp": true,
	"less": true, "more": true, "column": true, "tput": true, "clear": true,
	// Version control / editor housekeeping: IDEs (VSCode) poll these on a loop,
	// flooding the feed. They are benign regardless of args for our purposes, and
	// routing them to the 1B only makes it hallucinate. Prefilter them to benign.
	"git": true, "gitstatusd": true,
}

// sysDirs are the trusted directories a safe binary must live in. This stops a
// planted binary named after a coreutil (e.g. /home/x/ls) from being allowlisted
// by basename alone; temp-dir execs are additionally caught by looksRisky.
var sysDirs = []string{"/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/", "/usr/local/bin/", "/usr/local/sbin/"}

// shells are the interpreters that take a `-c "<command>"` script. A bare shell
// exec is benign; what matters is the inner command, handled by isBenignShellWrapper.
var shells = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "ash": true}

// riskySubstrings are signals that force a command to the LLM even when its
// executable is allowlisted (e.g. `cat /etc/shadow`, `tee ~/.ssh/authorized_keys`).
var riskySubstrings = []string{
	"/etc/shadow", "/etc/passwd", "/etc/sudoers", "/.ssh", "/etc/cron",
	"/etc/systemd/system", "/root/", "/dev/tcp", "mkfifo", "base64", "xxd",
	"curl", "wget", "chmod +x", "chmod 777", "chmod u+s", "ld_preload",
	"ld_library_path", "/proc/", "/dev/shm",
}

// looksRisky reports whether a command should be judged by the LLM rather than
// short-circuited. Reuses the mock heuristics (pipedToShell, isTempExec) plus a
// sensitive-content scan, so nothing risky is ever prefiltered to benign.
func looksRisky(e ExecEvent) bool {
	if isTempExec(e) {
		return true
	}
	cmd := strings.ToLower(e.CommandLine())
	if pipedToShell(cmd) {
		return true
	}
	for _, s := range riskySubstrings {
		if strings.Contains(cmd, s) {
			return true
		}
	}
	return false
}

// isAllowlisted reports whether executable is a known-safe system binary: a
// safe basename living in a trusted system directory.
func isAllowlisted(executable string) bool {
	if !safeBins[path.Base(executable)] {
		return false
	}
	for _, d := range sysDirs {
		if strings.HasPrefix(executable, d) {
			return true
		}
	}
	return false
}

// prefilter decides a command WITHOUT the LLM when it is clearly benign — a
// known-safe system binary with no risky content. Returns (result, true) to
// emit directly, or (_, false) to fall through to the cache/LLM path.
//
// Conservative by design: anything risky-looking, any interpreter/downloader,
// and any unknown executable returns false and reaches the model. The capacity
// win comes from the high volume of routine coreutils that this short-circuits.
func prefilter(e ExecEvent) (ScoreResult, bool) {
	if looksRisky(e) {
		return ScoreResult{}, false
	}
	reason := ""
	switch {
	case isAllowlisted(e.Executable):
		reason = "allowlisted system binary, no risk indicators"
	case isBenignShellWrapper(e):
		reason = "shell wrapper around an allowlisted command (e.g. IDE git polling)"
	default:
		return ScoreResult{}, false
	}
	return ScoreResult{
		RiskScore:      0.02,
		Verdict:        "benign",
		Reason:         reason,
		Mitre:          []string{},
		RiskIndicators: []string{},
	}, true
}

// isBenignShellWrapper recognizes `bash -c "<cmd>"` invocations whose inner
// command is itself an allowlisted program with no shell metacharacters — e.g.
// the IDE git poll `bash --norc -c "GIT_OPTIONAL_LOCKS=0 git diff --shortstat HEAD"`.
// Anything with a pipe / redirect / substitution / chaining is NOT treated as
// benign (it must reach the model), so `bash -c "curl x | sh"` is still scored.
// looksRisky has already run, so risky substrings (curl, /etc/shadow, …) are out.
func isBenignShellWrapper(e ExecEvent) bool {
	if !shells[path.Base(e.Executable)] {
		return false
	}
	inDir := false
	for _, d := range sysDirs {
		if strings.HasPrefix(e.Executable, d) {
			inDir = true
			break
		}
	}
	if !inDir {
		return false
	}
	// Extract the script that follows -c.
	payload := ""
	for i, a := range e.Argv {
		if a == "-c" && i+1 < len(e.Argv) {
			payload = e.Argv[i+1]
			break
		}
	}
	if payload == "" {
		return false
	}
	// Any shell metacharacter means real shell logic — let the model judge it.
	if strings.ContainsAny(payload, "|&;<>`$(){}\n") {
		return false
	}
	// Skip leading ENV=VAL assignments; the first bare token is the program.
	prog := ""
	for _, t := range strings.Fields(payload) {
		if strings.HasPrefix(t, "-") {
			return false // a flag before any program — unusual, let the model see it
		}
		if i := strings.IndexByte(t, '='); i > 0 && !strings.ContainsAny(t[:i], "/.") {
			continue // ENV=VAL assignment
		}
		prog = t
		break
	}
	return prog != "" && safeBins[path.Base(prog)]
}

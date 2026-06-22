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
}

// sysDirs are the trusted directories a safe binary must live in. This stops a
// planted binary named after a coreutil (e.g. /home/x/ls) from being allowlisted
// by basename alone; temp-dir execs are additionally caught by looksRisky.
var sysDirs = []string{"/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/"}

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
	if isAllowlisted(e.Executable) {
		return ScoreResult{
			RiskScore:      0.02,
			Verdict:        "benign",
			Reason:         "allowlisted system binary, no risk indicators",
			Mitre:          []string{},
			RiskIndicators: []string{},
		}, true
	}
	return ScoreResult{}, false
}

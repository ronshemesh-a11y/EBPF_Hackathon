package main

import "strings"

// Envelope mirrors the common fields present on EVERY P1 event, regardless of
// event_type (the P1→P2 JSON contract). P2 only reads a subset, but the full
// envelope is modeled so unknown event types still decode cleanly.
type Envelope struct {
	SchemaVersion int    `json:"schema_version"` // currently 1
	EventType     string `json:"event_type"`     // execve, execveat, fork, exit, setuid, memfd_create, chmod, openat, init_module
	Timestamp     string `json:"timestamp"`      // RFC3339 wall-clock
	KtimeNs       uint64 `json:"ktime_ns"`        // raw kernel monotonic ns
	PID           uint32 `json:"pid"`
	TID           uint32 `json:"tid"`
	UID           uint32 `json:"uid"`
	GID           uint32 `json:"gid"`
	Comm          string `json:"comm"` // acting process name (≤16 chars)
	CgroupID      uint64 `json:"cgroup_id"`
	DroppedSoFar  uint64 `json:"dropped_so_far"` // running ring-buffer drop counter
}

// ExecEvent is a decoded execve/execveat event: the common envelope plus the
// exec-specific payload P2 scores. ppid/parent_comm live in the exec payload
// (not the common envelope) per the P1 contract.
type ExecEvent struct {
	Envelope
	PPID          uint32   `json:"ppid"`
	ParentComm    string   `json:"parent_comm"`
	Executable    string   `json:"executable"`
	Argv          []string `json:"argv"` // real array, not joined
	ArgvTruncated bool     `json:"argv_truncated"`
	ArgClipped    bool     `json:"arg_clipped"`
	CWD           *string  `json:"cwd"`             // null if unresolvable
	LDPreload     *string  `json:"ld_preload"`      // null if not in envp
	LDLibraryPath *string  `json:"ld_library_path"` // null if not in envp
	IsExecveat    bool     `json:"is_execveat"`
}

// IsExec reports whether an event_type is one P2 should score. Everything else
// (fork/exit/openat/setuid/…) is decoded-and-skipped per the P1→P2 contract.
func IsExec(eventType string) bool {
	return eventType == "execve" || eventType == "execveat"
}

// CommandLine renders argv as a single string for the model prompt and the
// Verdict.command field. argv carries the program name in argv[0], so it is
// preferred; otherwise we fall back to the resolved executable path.
func (e ExecEvent) CommandLine() string {
	if len(e.Argv) > 0 {
		return strings.Join(e.Argv, " ")
	}
	return e.Executable
}

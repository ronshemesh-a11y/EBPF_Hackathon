package model

// Event is the JSON object emitted to stdout for every kernel event.
// Common envelope fields are always present; per-type fields use omitempty.
// Pointer fields (*string, *uint32) are nil → JSON null when not applicable.
type Event struct {
	// ── common envelope ────────────────────────────────────────
	SchemaVersion int    `json:"schema_version"`
	EventType     string `json:"event_type"`  // "execve", "fork", "exit", ...
	Timestamp     string `json:"timestamp"`   // RFC3339 wall-clock
	KtimeNs       uint64 `json:"ktime_ns"`
	PID           uint32 `json:"pid"`
	TID           uint32 `json:"tid"`
	UID           uint32 `json:"uid"`
	GID           uint32 `json:"gid"`
	Comm          string `json:"comm"`
	PPID          uint32 `json:"ppid"`
	ParentComm    string `json:"parent_comm"`
	CgroupID      uint64 `json:"cgroup_id"`
	DroppedSoFar  uint64 `json:"dropped_so_far"`

	// ── execve / execveat ──────────────────────────────────────
	Executable    string   `json:"executable,omitempty"`
	Argv          []string `json:"argv,omitempty"`
	ArgvTruncated bool     `json:"argv_truncated,omitempty"`
	ArgClipped    bool     `json:"arg_clipped,omitempty"`
	CWD           *string  `json:"cwd,omitempty"`            // null if unresolvable
	LDPreload     *string  `json:"ld_preload,omitempty"`     // null if not in envp
	LDLibraryPath *string  `json:"ld_library_path,omitempty"`
	IsExecveat    bool     `json:"is_execveat,omitempty"`

	// ── fork ───────────────────────────────────────────────────
	ChildPID *uint32 `json:"child_pid,omitempty"`

	// ── setuid / setreuid / setresuid ──────────────────────────
	// Syscall field also used for chmod ("chmod"/"fchmod") and module events.
	Syscall string  `json:"syscall,omitempty"`
	OldUID  *uint32 `json:"old_uid,omitempty"` // pointer: 0 is valid
	NewUID  *uint32 `json:"new_uid,omitempty"`

	// ── memfd_create ───────────────────────────────────────────
	Name  string `json:"name,omitempty"`
	Flags uint32 `json:"flags,omitempty"`

	// ── chmod / fchmod / openat ────────────────────────────────
	Filepath     string   `json:"filepath,omitempty"`
	Mode         uint32   `json:"mode,omitempty"`
	ModeOctal    string   `json:"mode_octal,omitempty"`
	OpenFlags    uint32   `json:"open_flags,omitempty"`
	FlagsDecoded []string `json:"flags_decoded,omitempty"`
}

const SchemaVersion = 1

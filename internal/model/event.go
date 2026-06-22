package model

// Event is the JSON object emitted to stdout for every execve.
// One object per line (JSONL).  Pointer fields are nil → JSON null / omitted.
type Event struct {
	// ── common envelope ────────────────────────────────────────
	SchemaVersion int    `json:"schema_version"`
	EventType     string `json:"event_type"` // always "execve"
	Timestamp     string `json:"timestamp"`  // RFC3339 wall-clock
	KtimeNs       uint64 `json:"ktime_ns"`
	PID           uint32 `json:"pid"`
	TID           uint32 `json:"tid"`
	UID           uint32 `json:"uid"`
	GID           uint32 `json:"gid"`
	Comm          string `json:"comm"`
	DroppedSoFar  uint64 `json:"dropped_so_far"`

	// ── execve ─────────────────────────────────────────────────
	Executable    string   `json:"executable,omitempty"`
	Argv          []string `json:"argv,omitempty"`
	ArgvTruncated bool     `json:"argv_truncated,omitempty"`
	ArgClipped    bool     `json:"arg_clipped,omitempty"`
	LDPreload     *string  `json:"ld_preload,omitempty"`     // null if not in envp
	LDLibraryPath *string  `json:"ld_library_path,omitempty"`
}

const SchemaVersion = 1

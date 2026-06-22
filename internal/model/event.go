package model

// Event is the JSON object emitted to stdout for every execve.
// One object per line (JSONL). schema_version + event_type satisfy the P1→P2
// contract (the scorer gates on event_type); executable + argv are the payload.
type Event struct {
	SchemaVersion int      `json:"schema_version"`
	EventType     string   `json:"event_type"` // always "execve"
	Executable    string   `json:"executable"` // resolved binary path
	Argv          []string `json:"argv"`       // command + arguments/flags as typed
}

const SchemaVersion = 1

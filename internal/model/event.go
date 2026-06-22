package model

// Event is the JSON object emitted to stdout for every execve.
// One object per line (JSONL). event_type satisfies the P1→P2 contract (the
// scorer gates on it); executable + argv are the payload.
type Event struct {
	EventType  string   `json:"event_type"` // always "execve"
	Executable string   `json:"executable"` // resolved binary path
	Argv       []string `json:"argv"`       // command + arguments/flags as typed
}

package model

// Event is the JSON object emitted to stdout for every execve.
// One object per line (JSONL). event_type satisfies the P1→P2 contract (the
// scorer gates on it); executable + argv are the payload.
type Event struct {
	EventType  string   `json:"event_type"` // always "execve"
	Executable string   `json:"executable"` // resolved binary path
	Argv       []string `json:"argv"`       // command + arguments/flags as typed
	// Provenance from task_struct. JSON tags match scorer's Envelope (pid/comm)
	// and ExecEvent (ppid/parent_comm) so the P1→P2 contract round-trips.
	PID        uint32 `json:"pid"`         // tgid of the exec'ing process
	PPID       uint32 `json:"ppid"`        // tgid of the parent
	Comm       string `json:"comm"`        // acting (pre-exec) process name
	ParentComm string `json:"parent_comm"` // parent process name
	Tty        string `json:"tty"`         // controlling terminal name ("" if none)
}

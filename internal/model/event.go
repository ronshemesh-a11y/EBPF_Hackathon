package model

// Event is the JSON object emitted to stdout for every execve.
// One object per line (JSONL): just the command that ran and its arguments.
type Event struct {
	Executable string   `json:"executable"` // resolved binary path
	Argv       []string `json:"argv"`       // command + arguments/flags as typed
}

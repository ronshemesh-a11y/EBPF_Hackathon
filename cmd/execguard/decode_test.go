package main

import "testing"

// TestDecodeEventPopulatesProvenance verifies the task_struct fields captured by
// the BPF program (pid/ppid/comm/parent_comm) survive decoding into model.Event.
func TestDecodeEventPopulatesProvenance(t *testing.T) {
	var raw bpfEvent
	copy(raw.Filename[:], toI8("/usr/bin/git"))
	copy(raw.ArgvBuf[:], toI8("git"))
	raw.ArgsCount = 1
	raw.Pid = 4242
	raw.Ppid = 100
	copy(raw.Comm[:], toI8("node"))
	copy(raw.Pcomm[:], toI8("code"))

	e := decodeEvent(&raw)
	if e.PID != 4242 || e.PPID != 100 {
		t.Fatalf("pid/ppid = %d/%d, want 4242/100", e.PID, e.PPID)
	}
	if e.Comm != "node" || e.ParentComm != "code" {
		t.Fatalf("comm/parent = %q/%q, want node/code", e.Comm, e.ParentComm)
	}
}

// toI8 copies a Go string into a null-terminated []int8 (the bpf2go char[] form).
func toI8(s string) []int8 {
	b := make([]int8, len(s)+1)
	for i := 0; i < len(s); i++ {
		b[i] = int8(s[i])
	}
	return b
}

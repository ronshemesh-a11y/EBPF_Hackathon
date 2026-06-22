package main

import (
	"unicode/utf8"

	"github.com/ronshemesh-a11y/EBPF_Hackathon/internal/model"
)

// decodeEvent converts a raw bpfEvent (bpf2go-generated) to the minimal
// command/argv model.Event.
func decodeEvent(raw *bpfEvent) model.Event {
	return model.Event{
		SchemaVersion: model.SchemaVersion,
		EventType:     "execve",
		Executable:    sanitize(int8SliceToStr(raw.Filename[:])),
		Argv:          decodeArgv(raw.ArgvBuf[:], raw.ArgsCount),
	}
}

// int8SliceToStr converts a null-terminated [N]int8 (bpf2go convention for char[]) to a Go string.
func int8SliceToStr(b []int8) string {
	end := len(b)
	for i, c := range b {
		if c == 0 {
			end = i
			break
		}
	}
	bs := make([]byte, end)
	for i, c := range b[:end] {
		bs[i] = byte(c)
	}
	return string(bs)
}

// decodeArgv splits the flat argv_buf into individual argument strings.
// Each slot is MAX_ARG_LEN (128) bytes, null-terminated.
func decodeArgv(buf []int8, count uint32) []string {
	const maxArgLen = 128
	if count == 0 {
		return nil
	}
	out := make([]string, 0, count)
	for i := uint32(0); i < count; i++ {
		start := i * maxArgLen
		if int(start) >= len(buf) {
			break
		}
		end := start + maxArgLen
		if int(end) > len(buf) {
			end = uint32(len(buf))
		}
		out = append(out, sanitize(int8SliceToStr(buf[start:end])))
	}
	return out
}

// sanitize replaces invalid UTF-8 sequences with the replacement character.
func sanitize(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		b = utf8.AppendRune(b, r)
		i += size
	}
	return string(b)
}

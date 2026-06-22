package main

import (
	"time"
	"unicode/utf8"

	"github.com/ronshemesh-a11y/EBPF_Hackathon/internal/enrich"
	"github.com/ronshemesh-a11y/EBPF_Hackathon/internal/model"
)

// decodeEvent converts a raw bpfEvent (bpf2go-generated struct) to a model.Event
// ready for JSON marshalling.
func decodeEvent(raw *bpfEvent, boot time.Time, droppedSoFar uint64) model.Event {
	e := model.Event{
		SchemaVersion: model.SchemaVersion,
		EventType:     "execve",
		KtimeNs:       raw.KtimeNs,
		Timestamp:     enrich.KtimeToWall(boot, raw.KtimeNs).UTC().Format(time.RFC3339Nano),
		PID:           raw.Pid,
		TID:           raw.Tid,
		UID:           raw.Uid,
		GID:           raw.Gid,
		Comm:          sanitize(int8SliceToStr(raw.Comm[:])),
		DroppedSoFar:  droppedSoFar,
	}

	e.Executable = sanitize(int8SliceToStr(raw.Filename[:]))
	e.Argv = decodeArgv(raw.ArgvBuf[:], raw.ArgsCount)
	e.ArgvTruncated = raw.ArgvTruncated != 0
	e.ArgClipped = raw.ArgClipped != 0
	if v := int8SliceToStr(raw.LdPreload[:]); v != "" {
		s := sanitize(v)
		e.LDPreload = &s
	}
	if v := int8SliceToStr(raw.LdLibraryPath[:]); v != "" {
		s := sanitize(v)
		e.LDLibraryPath = &s
	}

	return e
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

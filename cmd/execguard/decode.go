package main

import (
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/ronshemesh-a11y/EBPF_Hackathon/internal/enrich"
	"github.com/ronshemesh-a11y/EBPF_Hackathon/internal/model"
)

// event_type constants mirroring execguard.h
const (
	evtExec        = 1
	evtFork        = 2
	evtExit        = 3
	evtSetuid      = 4
	evtMemfd       = 5
	evtChmod       = 6
	evtFchmod      = 7
	evtOpenat      = 8
	evtInitModule  = 9
	evtFinitModule = 10
)

// decodeEvent converts a raw BpfEvent (bpf2go-generated struct) to a model.Event
// ready for JSON marshalling.  Returns (event, true) to emit, or (_, false) to drop.
func decodeEvent(raw *BpfEvent, boot time.Time, droppedSoFar uint64) (model.Event, bool) {
	e := model.Event{
		SchemaVersion: model.SchemaVersion,
		KtimeNs:       raw.KtimeNs,
		Timestamp:     enrich.KtimeToWall(boot, raw.KtimeNs).UTC().Format(time.RFC3339Nano),
		PID:           raw.Pid,
		TID:           raw.Tid,
		UID:           raw.Uid,
		GID:           raw.Gid,
		PPID:          raw.Ppid,
		Comm:          sanitize(int8SliceToStr(raw.Comm[:])),
		ParentComm:    sanitize(int8SliceToStr(raw.ParentComm[:])),
		CgroupID:      raw.CgroupId,
		DroppedSoFar:  droppedSoFar,
	}

	switch raw.EventType {
	case evtExec:
		e.EventType = "execve"
		e.Executable = sanitize(int8SliceToStr(raw.Filename[:]))
		e.Argv = decodeArgv(raw.ArgvBuf[:], raw.ArgsCount)
		e.ArgvTruncated = raw.ArgvTruncated != 0
		e.ArgClipped = raw.ArgClipped != 0
		e.IsExecveat = raw.IsExecveat != 0
		e.CWD = enrich.CWD(raw.Pid)
		if v := int8SliceToStr(raw.LdPreload[:]); v != "" {
			s := sanitize(v)
			e.LDPreload = &s
		}
		if v := int8SliceToStr(raw.LdLibraryPath[:]); v != "" {
			s := sanitize(v)
			e.LDLibraryPath = &s
		}

	case evtFork:
		e.EventType = "fork"
		child := raw.ChildPid
		e.ChildPID = &child

	case evtExit:
		e.EventType = "exit"

	case evtSetuid:
		e.EventType = "setuid"
		switch raw.SetuidVariant {
		case 0:
			e.Syscall = "setuid"
		case 1:
			e.Syscall = "setreuid"
		default:
			e.Syscall = "setresuid"
		}
		old := raw.OldUid
		nw := raw.NewUid
		e.OldUID = &old
		e.NewUID = &nw

	case evtMemfd:
		e.EventType = "memfd_create"
		e.Name = sanitize(int8SliceToStr(raw.Name[:]))
		e.Flags = raw.Flags

	case evtChmod:
		e.EventType = "chmod"
		e.Syscall = "chmod"
		e.Filepath = sanitize(int8SliceToStr(raw.Filepath[:]))
		e.Mode = raw.Mode
		e.ModeOctal = fmt.Sprintf("0%o", raw.Mode)

	case evtFchmod:
		e.EventType = "chmod"
		e.Syscall = "fchmod"
		path := enrich.FDPath(raw.Pid, raw.Fd)
		if !enrich.IsTmpExecPath(path) {
			return e, false
		}
		e.Filepath = sanitize(path)
		e.Mode = raw.Mode
		e.ModeOctal = fmt.Sprintf("0%o", raw.Mode)

	case evtOpenat:
		e.EventType = "openat"
		path := sanitize(int8SliceToStr(raw.Filepath[:]))
		if !enrich.IsSensitiveOpenatPath(path) {
			return e, false
		}
		e.Filepath = path
		e.OpenFlags = raw.OpenFlags
		e.FlagsDecoded = enrich.DecodeOpenFlags(raw.OpenFlags)

	case evtInitModule:
		e.EventType = "init_module"
		e.Syscall = "init_module"

	case evtFinitModule:
		e.EventType = "init_module"
		e.Syscall = "finit_module"
		fdPath := enrich.FDPath(raw.Pid, raw.Fd)
		if fdPath != "" {
			e.Name = enrich.ModuleName(fdPath)
		}
		e.Flags = raw.Flags

	default:
		return e, false
	}

	return e, true
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

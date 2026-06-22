package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event bpf ../../bpf/execguard.bpf.c -- -I../../bpf/headers -O2 -g -Wall

func main() {
	// -exclude drops execve events whose resolved executable path contains any
	// of these comma-separated substrings. Default skips the scoring backend
	// itself (Ollama / llama-server) so the AI doesn't score its own inference
	// process — a pure feedback-noise loop. Pass -exclude='' to emit everything,
	// or add desktop/system noise (e.g. -exclude='ollama,gjs,gnome-shell').
	excludeFlag := flag.String("exclude", "ollama,llama-server",
		"comma-separated substrings; skip execs whose executable path matches any")
	flag.Parse()
	excludes := parseExcludes(*excludeFlag)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock rlimit: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("load BPF objects: %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecve, nil)
	if err != nil {
		log.Fatalf("attach syscalls/sys_enter_execve: %v", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("open ring buffer reader: %v", err)
	}
	defer rd.Close()

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		rd.Close()
	}()

	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("ringbuf read: %v", err)
			continue
		}

		var raw bpfEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &raw); err != nil {
			log.Printf("decode bpfEvent: %v", err)
			continue
		}

		evt := decodeEvent(&raw)
		if excluded(evt.Executable, excludes) {
			continue
		}
		if err := enc.Encode(evt); err != nil {
			log.Printf("json encode: %v", err)
		}
	}
}

// parseExcludes splits the -exclude flag into a list of non-empty substrings.
func parseExcludes(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// excluded reports whether the executable path contains any exclude substring.
func excluded(executable string, excludes []string) bool {
	for _, e := range excludes {
		if strings.Contains(executable, e) {
			return true
		}
	}
	return false
}

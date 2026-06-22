package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event bpf ../../bpf/execguard.bpf.c -- -I../../bpf/headers -O2 -g -Wall

func main() {
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

		if err := enc.Encode(decodeEvent(&raw)); err != nil {
			log.Printf("json encode: %v", err)
		}
	}
}

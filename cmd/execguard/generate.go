//go:build ignore

package main

// bpf2go compiles execguard.bpf.c and generates:
//   bpf_bpfel.go / bpf_bpfeb.go  — Go bindings (committed to the repo)
//   bpf_bpfel.o  / bpf_bpfeb.o   — embedded ELF objects
//
// -type event generates a Go struct BpfEvent mirroring struct event in the C header.
// Run via: make generate   (or: go generate ./cmd/execguard/...)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event bpf ../../bpf/execguard.bpf.c -- -I../../bpf/headers -O2 -g -Wall

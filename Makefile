BINARY     := bin/execguard
VMLINUX    := bpf/headers/vmlinux.h
BPF_SRC    := bpf/execguard.bpf.c
GO_SRCS    := $(shell find cmd internal -name '*.go' ! -name '*_bpfeb.go')

.PHONY: all generate build run clean fmt vet vmlinux

all: build

# Generate vmlinux.h and copy libbpf headers (requires libbpf-dev installed).
# Must run on the target Linux host (not macOS).
vmlinux:
	mkdir -p bpf/headers
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)
	cp -r /usr/include/bpf bpf/headers/bpf

# Compile BPF C → Go bindings via bpf2go.
# Requires: clang, llvm, libelf-dev, vmlinux.h.
generate:
	cd cmd/execguard && go generate

# Build the Go binary (requires generated bpf_bpfel.go).
# -buildvcs=false: the repo is bind-mounted and owned by a different uid in the
# container, which trips git's "dubious ownership" check during VCS stamping.
build: $(GO_SRCS)
	go build -buildvcs=false -o $(BINARY) ./cmd/execguard

# Run as root (eBPF requires CAP_BPF / CAP_SYS_ADMIN).
run: build
	sudo $(BINARY)

# Run and pretty-print JSON.
run-pretty: build
	sudo $(BINARY) | jq .

deps:
	go mod tidy

fmt:
	gofmt -w .

vet:
	go vet ./...

clean:
	rm -f $(BINARY)
	rm -f cmd/execguard/bpf_bpfel.go cmd/execguard/bpf_bpfeb.go
	rm -f cmd/execguard/bpf_bpfel.o cmd/execguard/bpf_bpfeb.o

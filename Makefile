BINARY     := bin/execguard
VMLINUX    := bpf/headers/vmlinux.h
BPF_SRC    := bpf/execguard.bpf.c
GO_SRCS    := $(shell find cmd internal -name '*.go' ! -name '*_bpfeb.go')

.PHONY: all generate build run clean fmt vet vmlinux

all: build

# Generate vmlinux.h from the running kernel's BTF (requires bpftool).
# The libbpf BPF-side headers live in bpf/headers/bpf/ and are committed, so
# this only needs to produce vmlinux.h. Must run on the Linux host (not macOS).
vmlinux:
	mkdir -p bpf/headers
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

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

# ── End-to-end live pipeline ─────────────────────────────────────────────────
# sensor → scorer → web console on :8080. The scorer suppresses IDE/editor
# housekeeping noise (-suppress-parents) and the sensor excludes the inference
# backend from scoring itself. Build the scorer + server first:
#     (cd scorer && go build -o scorer .)
#     (cd exectrace && make ui && make build)
# Override the model with OLLAMA_MODEL=...; pass --mock to the scorer to run
# without a model. Open http://localhost:8080 once it's up.
.PHONY: pipeline
pipeline: build
	sudo $(BINARY) --tty-only | scorer/scorer --model $${OLLAMA_MODEL:-llama3.2:1b} | exectrace/bin/server --addr :8080

# Same, but ONLY the commands typed in one shell. Find its tty with `tty` in that
# shell (e.g. /dev/pts/1), then: make pipeline-session TTY=pts/1
.PHONY: pipeline-session
pipeline-session: build
	sudo $(BINARY) --tty=$(TTY) | scorer/scorer --model $${OLLAMA_MODEL:-llama3.2:1b} | exectrace/bin/server --addr :8080

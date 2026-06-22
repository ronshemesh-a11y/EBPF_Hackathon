# exectrace — Person 3 slice (output + eval + integration)
# Everything here runs on sample data with no eBPF and no LLM.

GO     ?= go
BINDIR := bin
FILE   ?= testdata/sample.csv
RATE   ?= 0
THRESHOLD ?= GRAY
OUT    ?=
TRUTH  ?=

.PHONY: all build ui replay report eval bench compare pipe serve live web-offline test clean tidy

all: build

# Build the React SOC console into internal/server/dist (embedded by the Go
# server). Run this before `build` whenever the UI changes.
ui:
	cd web && npm install && npm run build

build:
	@mkdir -p $(BINDIR)
	$(GO) build -o $(BINDIR)/replay  ./cmd/replay
	$(GO) build -o $(BINDIR)/report  ./cmd/report
	$(GO) build -o $(BINDIR)/eval    ./cmd/eval
	$(GO) build -o $(BINDIR)/compare ./cmd/compare
	$(GO) build -o $(BINDIR)/server  ./cmd/server

# Stream events from a corpus as NDJSON (the bridge for the whole pipeline).
#   make replay FILE=testdata/sample.csv RATE=5
replay: build
	$(BINDIR)/replay --file $(FILE) --rate $(RATE)

# Read NDJSON events on stdin, score, print banded alerts (LOW hidden by default).
#   make replay FILE=... | make report
report: build
	$(BINDIR)/report --threshold $(THRESHOLD)

# End-to-end demo: replay piped into report.
#   make pipe FILE=testdata/sample.csv
pipe: build
	$(BINDIR)/replay --file $(FILE) --rate $(RATE) | $(BINDIR)/report --threshold $(THRESHOLD)

# Web server: read Verdict NDJSON on stdin, serve the live page on :8080.
#   ... | make serve          (e.g. report --scorer llm --json | server)
serve: build
	$(BINDIR)/server

# LIVE, REAL pipeline — the only path that should feed the served dashboard:
# real eBPF execs from execguard, scored by the real LLM, into the server.
# Needs root (eBPF) + Ollama running. execguard is the P1 binary at repo root.
#   make live  → open http://localhost:8080, then run real commands
EXECGUARD ?= ../bin/execguard
MODEL     ?= llama3.2:1b
live: build
	sudo $(EXECGUARD) | $(BINDIR)/report --scorer llm --model $(MODEL) --json --threshold LOW | $(BINDIR)/server --ingest "live execguard · scorer: llm ($(MODEL))"

# DEV ONLY — NOT real data. Replay a CSV through the mock scorer for offline UI
# work. Never use this for the demo; the served dashboard must show real execs.
#   make web-offline FILE=testdata/sample.csv
web-offline: build
	$(BINDIR)/replay --file $(FILE) --rate $(RATE) | $(BINDIR)/report --json --threshold LOW | $(BINDIR)/server --db /tmp/exectrace-offline.db --ingest "OFFLINE replay · mock (dev only)"

# Benchmark against the label column, optionally persisting to OUT.
#   make eval FILE=testdata/sample.csv OUT=results.json
eval: build
	$(BINDIR)/eval --file $(FILE) $(if $(OUT),--out $(OUT),) $(if $(TRUTH),--truth $(TRUTH),)

# Scorecard mode: full benchmark with FP/missed lists.
#   make bench FILE=testdata/attack_linux_labeled.csv
#   make bench FILE=corpus.csv TRUTH=testdata/attack_linux_ground_truth.txt OUT=run.json
bench: build
	$(BINDIR)/eval --file $(FILE) $(if $(TRUTH),--truth $(TRUTH),) $(if $(OUT),--out $(OUT),)

# Compare two persisted runs (A=baseline B=new).
#   make compare A=run1.json B=run2.json
compare: build
	$(BINDIR)/compare $(A) $(B)

test:
	$(GO) test ./...

tidy:
	$(GO) mod tidy

clean:
	rm -rf $(BINDIR)

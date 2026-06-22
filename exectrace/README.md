# exectrace — Person 3 slice (output + evaluation + integration)

This is the **output / eval / integration** third of `exectrace`. It runs on
sample data **today** — no eBPF, no LLM — and is wired so that going live later
changes nothing here.

```
 source            scorer            output
┌────────────┐   ┌──────────┐   ┌──────────────┐
│ replay CSV │   │  mockp2  │   │  report      │  banded alerts + summary
│   (or)     │──▶│  (TEMP)  │──▶│  eval        │  recall / precision / TP / FP
│ live eBPF  │   │ → real P2│   │              │
└────────────┘   └──────────┘   └──────────────┘
   types.Event       types.Verdict
```

The two structs in [internal/types](internal/types/types.go) are the only seam:
`Event` is what any source emits; `Verdict` is what any scorer produces.

## Quick start

```bash
make build

# End-to-end demo (replay piped into the reporter), LOW hidden by default:
make pipe FILE=testdata/sample.csv

# Or run the two halves yourself:
bin/replay --file testdata/sample.csv | bin/report --threshold GRAY

# Benchmark against the label column:
make eval FILE=testdata/sample.csv
```

## Components

| Path | Role |
|------|------|
| [internal/types](internal/types/types.go) | `Event` + `Verdict` — the contracts. **Reconcile `Verdict` with P2 before wiring real data.** |
| [internal/source](internal/source/csv.go) | CSV → `[]Event` bridge (shared by replay + eval, so they parse identically). |
| [cmd/replay](cmd/replay/main.go) | Emits NDJSON `Event`s on stdout at `--rate`. Source-agnostic: output is byte-for-byte what live eBPF would emit. |
| [internal/mockp2](internal/mockp2/mockp2.go) | **TEMP** regex scorer standing in for real P2. Deterministic, no LLM. |
| [internal/report](internal/report/report.go) + [cmd/report](cmd/report/main.go) | Consume `Verdict`s, print banded lines, hide below `--threshold`, summarize on exit. |
| [internal/eval](internal/eval/eval.go) + [cmd/eval](cmd/eval/main.go) | TP/FP/recall/precision vs the `label` column (or a separate `--truth` file). |

## Design rules honored

- **Stream-first.** Replay emits one event at a time; report and eval accumulate
  per-event. Nothing assumes a total count or a fixed number of malicious rows.
- **Source-agnostic.** `replay` and a future live tracer both emit `types.Event`
  NDJSON. The reporter/eval read that stream and cannot tell the difference.
- **Threshold is config.** Band cutoffs (`--gray`, `--high`) and the display
  threshold (`--threshold`) are flags, not hardcoded constants.
- **Contract is sacred.** `Verdict` is the seam with P2. `mockp2` matches it
  exactly. **Confirm any field change with P2 before building real wiring.**

## Swapping in real P2

`mockp2` is marked TEMP. Replacing it touches **one line** in
[cmd/report/main.go](cmd/report/main.go) and [cmd/eval/main.go](cmd/eval/main.go) —
the `scorer := mockp2.New(...)` call. As long as the real scorer returns
`types.Verdict` with the same fields, the reporter, eval, replay, and types
packages are unchanged.

## Corpus format

`testdata/sample.csv` is `process_name,command_line[,label]`. The header row is
auto-detected. The `label` column is **only** a benchmark/demo input — it is
carried separately (`source.Row.Label`) and never reaches an `Event`, so it
cannot leak into a runtime assumption. Labels treated as threats:
`malicious`, `suspicious` (see `eval.IsPositive`).

## Make targets

| Target | Does |
|--------|------|
| `make build` | build `replay`, `report`, `eval` into `bin/` |
| `make replay FILE=… RATE=…` | stream a corpus as NDJSON events |
| `make report` | read NDJSON on stdin, score + print alerts |
| `make pipe FILE=…` | replay \| report, end to end |
| `make eval FILE=…` | benchmark against the label column |
| `make test` | unit tests (eval math, CSV parsing) |
| `make clean` | remove `bin/` |

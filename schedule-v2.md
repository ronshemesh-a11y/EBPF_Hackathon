# Schedule v2 — Iterative Build (terminal-first)

**Principle:** every iteration ships a **working end-to-end slice** (exec → score → terminal), not a horizontal layer. You always have something that runs and demos. Reuse the SENTRY brain + PhantomTrace corpus so you're tuning, not inventing.

## Roles

- **P1 — eBPF / Kernel (C):** get live execs (with argv) out of the kernel.
- **P2 — Collector + Scoring + LLM (Go):** the brain — normalize, port SENTRY's banded patterns/combos, LLM confirmation.
- **P3 — Output + Eval + Integration:** terminal reporter, threshold/Slack, the corpus replay + eval harness, Makefile/run, README, demo.

## Iterations

### Iteration 0 — Walking skeleton *(everyone, ~first block)*
Goal: the pipe exists end-to-end, even if dumb.
- P1: `execve` eBPF → ring buffer → Go prints `pid + argv`. **(Milestone 1)**
- P3: repo + Makefile (`generate/build/run`) + a **replay injector** that reads `mini.csv` and feeds rows into the collector (unblocks P2/P3 before eBPF is ready).
- P2: collector skeleton that consumes either source and prints.
- **Exit:** `sudo ./exectrace` prints every command live; replay prints the CSV. ✅

### Iteration 1 — Deterministic detection *(P2 lead)*
Goal: flag commands with a score + reason, no LLM yet.
- P2: port SENTRY `standalone` (Linux subset) + `baselines` + `scoring.py` bands to Go; emit Verdict lines.
- P3: terminal reporter (band/score/reason/MITRE) + threshold filter (show GRAY/HIGH); **eval harness v1** — run the 220-row set, compare flags to `ground_truth.txt`, print recall/precision.
- **Exit:** deterministic-only run on the corpus reports its TP/FP. **(Milestone 2, rules-only)** ✅

### Iteration 2 — LLM confirmation *(P2 lead)*
Goal: cut false positives, add reasoning.
- P2: GRAY band → Phi-3 (Ollama) confirm/prune (mirror `ai_confirm.py`: PRUNE/VERIFY/HUNT); strict JSON; allowlist cache by `hash(argv)`.
- P3: re-run eval; show precision/recall **with vs without** the LLM (great demo slide).
- **Exit:** LLM measurably improves the score on the corpus. ✅

### Iteration 3 — Correlation + Slack *(P2 + P3)*
Goal: catch sequences; route alerts out.
- P2: port `combos.py` (31 correlations) — flag groups that are benign alone but malicious together, across the stream.
- P3: **Slack sink** for HIGH/confirmed; threshold config via flags/env.
- **Exit:** a multi-step sequence in the corpus is caught as one campaign; HIGH alerts hit Slack. ✅

### Iteration 4 — Behavioral hooks + polish *(P1 + all)*
Goal: live reverse-shell signal + demo.
- P1: add `connect` + `dup2` + `fork`/`exit`; collector correlates `connect→dup2→exec`.
- All: tune thresholds on the 220-set; rehearse the **replay demo**; write README (trade-offs + local-vs-hosted LLM).
- **Exit:** live reverse shell flagged; clean replay demo locked; README done. ✅

> Iterations 0–2 are the must-have (they satisfy the hackathon milestones and produce a working detector). 3–4 are high-value once the core is solid.

## Per-person task lists

**P1 — eBPF (C)**
- [ ] Toolchain check (clang, go 1.21+, kernel 5.8+, BTF, sudo).
- [ ] `execve` → ring buffer with full argv (Iter 0 / M1).
- [ ] `bpf2go` wired into the Makefile.
- [ ] `connect` + `dup2`(newfd∈{0,1,2}) + `fork`/`exit` (Iter 4).
- [ ] README trade-off notes (failed execs? argv cap? comm new vs parent?).
- [ ] After M1, **pair into P2's collector** (shared struct boundary).

**P2 — Collector + Scoring + LLM (Go)**
- [ ] Ringbuf reader + decode + normalize argv.
- [ ] Port SENTRY `standalone` + `baselines` + bands → Go scoring (Iter 1).
- [ ] Verdict struct/JSON to P3.
- [ ] Phi-3/Ollama confirm pass on GRAY + strict JSON + allowlist cache (Iter 2).
- [ ] Port `combos.py` correlation across the stream (Iter 3).
- [ ] Keep a deterministic-only mode (works with no LLM).

**P3 — Output + Eval + Integration**
- [ ] Repo + Makefile + replay injector (CSV → synthetic execs) (Iter 0).
- [ ] Terminal reporter (band/score/reason/MITRE) + threshold filter (Iter 1).
- [ ] **Eval harness:** run the 220-set, score vs `ground_truth.txt`, report recall/precision (Iter 1, rerun each iter).
- [ ] Slack webhook sink + threshold config (Iter 3).
- [ ] `events.jsonl` capture + clean demo replay; README + pitch (Iter 4).

## Critical path & load balance

- **Long pole:** P1's eBPF — but P3's replay injector (reading `mini.csv` / a PhantomTrace dataset) means P2 and P3 build the *entire* detector + eval on synthetic execs **before the kernel works**. The corpus de-risks the schedule.
- **Heaviest seat:** P2 (port + LLM). Mitigations: Claude auto-translates the SENTRY pattern tables to Go; P1 pairs in after M1; push the `combos` port and allowlist cache to stretch if needed.
- **Win condition:** Iterations 0–2 done = a working, measured detector. Everything else is upside.

## Demo (replay-based, deterministic)

Run a PhantomTrace Linux dataset through the live pipeline: the terminal flags the ~20 malicious commands with reasons + MITRE, keeps false positives near zero on the benign twins, shows the LLM rescuing a sequence the rules alone missed, and (optionally) pings Slack on the HIGH hits — all off a recorded run so it never flakes.

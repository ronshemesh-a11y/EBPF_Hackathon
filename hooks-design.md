# eBPF Hooks Design

## V1 — Standalone Malicious Command Detection

Goal: flag individual commands that are suspicious in isolation. A single event tells the full story — no cross-event correlation needed.

| Hook | Fields Collected | Filter | Attack Covered |
|------|-----------------|--------|----------------|
| `execve` / `execveat` | pid, ppid, argv[], uid, cwd, parent_comm, LD_PRELOAD + LD_LIBRARY_PATH from envp | none | Core hook — LOLbins, suspicious argv patterns, LD_PRELOAD hijack, dropper execution |
| `sched_process_fork` | parent_pid, child_pid, parent_comm | none | Parent context only — makes execve events meaningful (nginx spawning bash is the signal) |
| `sched_process_exit` | pid | none | Map cleanup |
| `sys_enter_setuid` / `setreuid` / `setresuid` | pid, old_uid, new_uid | new_uid == 0 only | Privilege escalation — uid flip to root is suspicious standalone |
| `memfd_create` | pid, name, flags | none | Fileless malware — in-memory execution, no legitimate process does this at runtime |
| `sys_enter_chmod` / `fchmod` | pid, filepath, mode | path prefix `/tmp/`, `/dev/shm/`, `/var/tmp/` AND mode has +x | Dropper staging — writing and making a file executable in a temp dir |
| `sys_enter_openat` | pid, filepath, flags | path prefix: `/etc/shadow`, `/etc/passwd`, `/root/.ssh/`, `/proc/*/mem`, `/var/spool/cron/`, `/etc/cron*`, `/etc/systemd/system/` | Credential access, persistence — single access to these paths is suspicious on its own |
| `init_module` / `finit_module` | pid, module_name | none | Rootkit loading — always escalate, no correlation needed |

**What V1 sends to Phi-3:** single enriched event + its ancestor chain (ppid walk). No cross-event correlation. The LLM asks: "is this one command suspicious given who spawned it?"

---

## V2 — Multi-Step Attack Detection (adds to V1)

Goal: detect attacks that only become visible when correlating events across time and across hooks. V2 includes all V1 hooks plus these:

| Hook | Fields Collected | Filter | Attack Covered |
|------|-----------------|--------|----------------|
| `sys_enter_connect` | pid, fd, sa_family, dest_ip, dest_port | sa_family == AF_INET or AF_INET6 only | Reverse shell C2, lateral movement, port scanning, download-and-execute |
| `sys_enter_dup2` / `dup3` | pid, oldfd, newfd | newfd == 0, 1, or 2 only | Reverse shell fd redirect — only meaningful combined with connect() |
| `sys_enter_ptrace` | pid, request, target_pid | request == PTRACE_POKETEXT or PTRACE_POKEDATA only | Process injection — shellcode written into another process's memory |
| `sys_enter_mount` | pid, source, target, filesystemtype, flags | none | Container escape — requires context of what's being mounted and from where |

**What V2 adds to the pipeline:** a per-pid event timeline in Go that correlates across hook types. Detection rules fire when a sequence is complete — e.g. connect() + dup2(sockfd→stdin/stdout) + execve(bash) from the same pid = reverse shell. Single events from V2 hooks are not meaningful alone.

---

## Full Attack Coverage Map

| Attack | V1 | V2 | Hooks Involved |
|--------|----|----|----------------|
| Suspicious single command (LOLbin) | ✓ | ✓ | execve |
| LD_PRELOAD hijack | ✓ | ✓ | execve (envp) |
| Privilege escalation | ✓ | ✓ | setuid + execve |
| Credential access | ✓ | ✓ | openat |
| Persistence (cron/systemd) | ✓ | ✓ | openat |
| Dropper staging | ✓ | ✓ | chmod + execve |
| Fileless malware | ✓ | ✓ | memfd_create |
| Rootkit loading | ✓ | ✓ | init_module |
| Reverse shell | — | ✓ | connect + dup2 + execve |
| Download-and-execute | — | ✓ | connect + execve |
| Port scanning | — | ✓ | connect (flood pattern) |
| SSH lateral movement | — | ✓ | connect(:22) + execve(ssh) |
| Process injection | — | ✓ | ptrace POKE |
| Container escape | — | ✓ | mount |

---

## Known Blind Spots (both versions)

- Memory shellcode via mmap/mprotect — JIT compiler noise too high to hook
- DNS exfiltration via raw sockets — requires packet reconstruction, out of scope
- Attacks inside an already-running process (no exec, no connect) — no clean hook available

# eBPF Hooks Design

## Hook Table

| Hook | Fields Collected | Filter | Attack Coverage |
|------|-----------------|--------|-----------------|
| `execve` / `execveat` | pid, ppid, argv[], uid, cwd, parent_comm, LD_PRELOAD/LD_LIBRARY_PATH from envp | none — catch all | Droppers, LOLbins, reverse shell spawn, LD_PRELOAD hijack, living-off-the-land |
| `sched_process_fork` | parent_pid, child_pid, parent_comm | none | Process tree maintenance — gives lineage context to all other hooks |
| `sched_process_exit` | pid | none | Map cleanup / eviction |
| `sys_enter_connect` | pid, fd, sa_family, dest_ip, dest_port | sa_family == AF_INET or AF_INET6 only | Reverse shell C2 connection, lateral movement, port scanning, download-and-execute |
| `sys_enter_dup2` / `dup3` | pid, oldfd, newfd | newfd == 0, 1, or 2 only (stdin/stdout/stderr) | Reverse shell fd-to-socket redirect — smoking gun when combined with connect() |
| `sys_enter_openat` | pid, filepath, flags | path prefix: `/etc/shadow`, `/etc/passwd`, `/root/.ssh/`, `/proc/*/mem`, `/var/spool/cron/`, `/etc/cron*`, `/etc/systemd/system/` | Credential access, persistence (cron/systemd), SSH key theft |
| `sys_enter_setuid` / `setreuid` / `setresuid` | pid, old_uid, new_uid | new_uid == 0 only | Privilege escalation — uid flip to root after suspicious exec chain |
| `memfd_create` | pid, name, flags | none — inherently low frequency | Fileless malware — in-memory execution without touching disk |
| `sys_enter_ptrace` | pid, request, target_pid | request == PTRACE_POKETEXT or PTRACE_POKEDATA only | Process injection — shellcode written into another process's memory |
| `sys_enter_chmod` / `fchmod` | pid, filepath, mode | path prefix: `/tmp/`, `/dev/shm/`, `/var/tmp/` AND new mode has +x | Dropper pattern — file written to temp dir then made executable |
| `sys_enter_mount` | pid, source, target, filesystemtype, flags | none — mounts are rare | Container escape — unexpected mount of host filesystem or sensitive paths |
| `init_module` / `finit_module` | pid, module_name | none — extremely rare | Rootkit loading — always escalate to heavy model |

---

## Attack Coverage Summary

| Attack | Primary Hook(s) | Confirmed By |
|--------|----------------|--------------|
| Reverse shell | connect() + dup2() + execve | All three together in same pid timeline |
| Download-and-execute dropper | connect() + execve | curl/wget argv + exec of downloaded file |
| Living-off-the-land (LOLbins) | execve | LLM flags suspicious argv on trusted binaries |
| LD_PRELOAD hijack | execve (envp) | LD_PRELOAD set on suspicious exec |
| Privilege escalation | setuid + execve | uid flip to 0 after suspicious exec chain |
| Credential access | openat | Access to /etc/shadow, /proc/*/mem etc. |
| Persistence | openat | Write to cron, systemd, SSH authorized_keys |
| Fileless malware | memfd_create + execve | memfd path in execve (/proc/self/fd/X) |
| Process injection | ptrace (POKE only) | PTRACE_POKETEXT/DATA on non-child process |
| Dropper staging | chmod | +x on file in /tmp or /dev/shm |
| Container escape | mount | Unexpected mount in containerized pid |
| Rootkit loading | init_module | Any module load post-boot — always alert |
| Port scanning | connect() | connect() flood from single pid |
| Lateral movement (SSH) | connect() + execve | connect to :22 + ssh in exec lineage |

---

## Context Sent to Phi-3 Per Event

Two separate blocks, clearly labeled:

**Block 1 — Ancestor chain** (who spawned this process)
- Resolved from pid→ppid map, typically 3–5 hops
- Fields per node: comm, argv, uid, timestamp

**Block 2 — Recent suspicious events** (cross-process pattern context)
- Last N flagged events from any pid, with time deltas
- Enables multi-step attack detection across unrelated processes

---

## Known Blind Spots (document in README)

- Memory-only shellcode via mmap/mprotect — skipped, JIT compiler noise too high
- Full credential read content (read() on /etc/shadow) — openat tells us access happened, content tracking too complex
- DNS exfiltration via raw sockets — requires packet reconstruction, out of scope
- mmap-based injection without ptrace — no clean low-noise hook available

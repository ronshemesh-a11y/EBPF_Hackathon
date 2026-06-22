# Event stream samples

The eBPF collector (`bin/execguard`) emits **line-delimited JSON** (JSONL) to
stdout — one event object per line. Your consumer reads this from stdin.

## Integration

Live:

```sh
sudo ./bin/execguard | your_consumer
```

Replay a captured sample (no root, no kernel needed — pure stdin):

```sh
cat samples/sample-events.jsonl | your_consumer
```

## Contract

- One JSON object per line, UTF-8.
- Every line has the common envelope: `schema_version, event_type, timestamp,
  ktime_ns, pid, tid, uid, gid, comm, ppid, parent_comm, cgroup_id,
  dropped_so_far`.
- `event_type` is one of: `execve`, `fork`, `exit`, `setuid`, `memfd_create`,
  `chmod`, `openat`, `init_module`.
- Per-type fields are only present when relevant (absent/omitted otherwise).
  Pointer-like fields (`cwd`, `ld_preload`, `ld_library_path`, `old_uid`,
  `new_uid`, `child_pid`) may be `null` or absent.
- `dropped_so_far` is a running count of ring-buffer drops — if it climbs,
  the consumer is too slow / volume too high (should stay 0 in normal use).

## Per-type fields

| event_type     | extra fields |
|----------------|--------------|
| `execve`       | `executable, argv[], argv_truncated, arg_clipped, cwd, ld_preload, ld_library_path, is_execveat` |
| `fork`         | `child_pid` |
| `exit`         | (envelope only; `pid` is the exiting process) |
| `setuid`       | `syscall` (setuid/setreuid/setresuid), `old_uid`, `new_uid` |
| `memfd_create` | `name`, `flags` |
| `chmod`        | `syscall` (chmod/fchmod), `filepath`, `mode`, `mode_octal` |
| `openat`       | `filepath`, `open_flags`, `flags_decoded[]` |
| `init_module`  | `syscall` (init_module/finit_module), `name` (finit only), `flags` |

In-kernel filtering already applies: `openat` only surfaces sensitive paths,
`setuid` only root targets, `chmod` only +x in temp dirs. The consumer sees a
pre-filtered, security-relevant stream — not every syscall.

# Event stream samples

The eBPF collector (`bin/execguard`) emits **line-delimited JSON** (JSONL) to
stdout — one event object per line. Your consumer reads this from stdin.

The collector hooks a single tracepoint: **`execve`**. Every line is an
`execve` event.

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

One JSON object per line, UTF-8. Fields:

| Field | Type | Notes |
|-------|------|-------|
| `schema_version` | int | currently `1` |
| `event_type` | string | always `"execve"` |
| `timestamp` | string | RFC3339 wall-clock |
| `ktime_ns` | uint64 | kernel monotonic ns since boot |
| `pid` / `tid` | uint32 | process / thread id |
| `uid` / `gid` | uint32 | caller's user / group id |
| `comm` | string | calling process name (e.g. `bash` execing `cat`) |
| `dropped_so_far` | uint64 | running ring-buffer drop count (should stay 0) |
| `executable` | string | resolved binary path (execve `filename` arg) |
| `argv` | []string | argument vector, up to 20 args × 128 bytes each |
| `argv_truncated` | bool | true if more than 20 args were passed |
| `arg_clipped` | bool | true if any single arg exceeded 128 bytes |
| `ld_preload` | string \| null | `LD_PRELOAD` value from envp, null if unset |
| `ld_library_path` | string \| null | `LD_LIBRARY_PATH` value from envp, null if unset |

`omitempty` applies: false bools and empty/null optional fields may be absent.

## Example

```json
{"schema_version":1,"event_type":"execve","timestamp":"2026-06-22T11:34:53.075564435Z","ktime_ns":9706062595035,"pid":12219,"tid":12219,"uid":0,"gid":0,"comm":"bash","dropped_so_far":0,"executable":"/usr/bin/cat","argv":["cat","/etc/shadow"]}
```

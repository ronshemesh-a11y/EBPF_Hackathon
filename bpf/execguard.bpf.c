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

/* 16 MB ring buffer carrying execve events to userspace. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

/* ── execve ──────────────────────────────────────────────────────────────── */

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
	const char *filename    = (const char *)ctx->args[0];
	const char *const *argv = (const char *const *)ctx->args[1];

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->args_count = 0;
	bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

	/* argv walk — read each pointer, then the string it points to. */
	#pragma unroll
	for (int i = 0; i < MAX_ARGS; i++) {
		const char *argp = NULL;
		if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) < 0 || !argp)
			break;
		bpf_probe_read_user_str(&e->argv_buf[i * MAX_ARG_LEN], MAX_ARG_LEN, argp);
		e->args_count = i + 1;
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

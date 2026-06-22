#pragma once

#define TASK_COMM_LEN    16
#define MAX_FILENAME_LEN 256
#define MAX_ARGS         20
#define MAX_ARG_LEN      128
#define ARGV_BUF_SIZE    (MAX_ARGS * MAX_ARG_LEN)  /* 2560 */
#define MAX_ENVP         48
#define LD_PRELOAD_LEN   128
#define LD_LIBPATH_LEN   256

enum event_type {
	EVENT_EXEC = 1,  /* execve */
};

/*
 * Single execve event.  Built directly in the ring buffer (it exceeds the
 * 512-byte BPF stack limit), so no per-CPU scratch / memcpy is needed.
 */
struct event {
	/* ── common envelope ──────────────────────────────────────── */
	__u64 ktime_ns;
	__u32 event_type;
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u32 gid;
	char  comm[TASK_COMM_LEN];

	/* ── exec payload ─────────────────────────────────────────── */
	char  filename[MAX_FILENAME_LEN];
	char  argv_buf[ARGV_BUF_SIZE];
	__u32 args_count;
	__u8  argv_truncated;
	__u8  arg_clipped;
	__u8  reserved0;
	__u8  reserved1;
	char  ld_preload[LD_PRELOAD_LEN];
	char  ld_library_path[LD_LIBPATH_LEN];
};

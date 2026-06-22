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
	EVENT_EXEC          = 1,  /* execve + execveat (is_execveat flag) */
	EVENT_FORK          = 2,
	EVENT_EXIT          = 3,
	EVENT_SETUID        = 4,  /* setuid / setreuid / setresuid (setuid_variant) */
	EVENT_MEMFD         = 5,
	EVENT_CHMOD         = 6,  /* chmod — path in filepath */
	EVENT_FCHMOD        = 7,  /* fchmod — fd in e->fd, path resolved in Go */
	EVENT_OPENAT        = 8,
	EVENT_INIT_MODULE   = 9,
	EVENT_FINIT_MODULE  = 10,
};

/*
 * Single tagged event struct shared by all hooks.  Built in per-CPU scratch
 * (it exceeds the 512-byte BPF stack limit), then copied to the ring buffer.
 *
 * Offsets are manually kept 4/8-byte aligned so binary.Read in Go works
 * without surprises.
 */
struct event {
	/* ── common envelope (offset 0) ───────────────────────────── */
	__u64 ktime_ns;           /* 0  */
	__u64 cgroup_id;          /* 8  */
	__u32 event_type;         /* 16 */
	__u32 pid;                /* 20 */
	__u32 tid;                /* 24 */
	__u32 uid;                /* 28 */
	__u32 gid;                /* 32 */
	__u32 ppid;               /* 36 */
	char  comm[TASK_COMM_LEN];         /* 40 – 55  */
	char  parent_comm[TASK_COMM_LEN];  /* 56 – 71  */

	/* ── exec payload ─────────────────────────────────────────── */
	char  filename[MAX_FILENAME_LEN];  /* 72  – 327  */
	char  argv_buf[ARGV_BUF_SIZE];     /* 328 – 2887 */
	__u32 args_count;                  /* 2888 */
	__u8  argv_truncated;              /* 2892 */
	__u8  arg_clipped;                 /* 2893 */
	__u8  is_execveat;                 /* 2894 */
	__u8  reserved0;                   /* 2895 */
	char  ld_preload[LD_PRELOAD_LEN];  /* 2896 – 3023 */
	char  ld_library_path[LD_LIBPATH_LEN]; /* 3024 – 3279 */

	/* ── fork ──────────────────────────────────────────────────── */
	__u32 child_pid;          /* 3280 */

	/* ── setuid ────────────────────────────────────────────────── */
	__u32 old_uid;            /* 3284 */
	__u32 new_uid;            /* 3288 */
	__u32 setuid_variant;     /* 3292  0=setuid 1=setreuid 2=setresuid */

	/* ── memfd / module ────────────────────────────────────────── */
	char  name[MAX_FILENAME_LEN]; /* 3296 – 3551 */
	__u32 flags;              /* 3552 */

	/* ── chmod / fchmod / openat / finit_module ────────────────── */
	char  filepath[MAX_FILENAME_LEN]; /* 3556 – 3811 */
	__u32 mode;               /* 3812 */
	__u32 open_flags;         /* 3816 */
	__u32 fd;                 /* 3820  fchmod fd or finit_module fd */
};
/* total: 3824 bytes */

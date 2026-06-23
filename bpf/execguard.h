#pragma once

#define MAX_FILENAME_LEN 256
#define MAX_ARGS         20
#define MAX_ARG_LEN      128
#define ARGV_BUF_SIZE    (MAX_ARGS * MAX_ARG_LEN)  /* 2560 */
#define TTY_LEN          64
#define TASK_COMM_LEN    16

/*
 * Minimal execve event: the resolved binary, the argument vector, the
 * controlling terminal name ("" if none — used by --tty-only to drop ttyless
 * daemon/IDE/cron noise), and per-process provenance read from task_struct.
 * Built directly in the ring buffer (exceeds the 512-byte BPF stack limit).
 *
 * Provenance: pid/ppid are thread-group ids (the "process" pids). comm is the
 * ACTING name at execve-enter — because the caller has fork()'d but not yet
 * replaced its image, this is the spawner's name (e.g. "node"/"code" for an IDE
 * git poll, "bash" for a shell command). pcomm is the parent's name. Together
 * they attribute an exec to who launched it, which userspace uses to drop
 * editor/IDE housekeeping noise.
 */
struct event {
	char  filename[MAX_FILENAME_LEN];
	char  argv_buf[ARGV_BUF_SIZE];
	__u32 args_count;
	char  tty[TTY_LEN];
	__u32 pid;
	__u32 ppid;
	char  comm[TASK_COMM_LEN];
	char  pcomm[TASK_COMM_LEN];
};

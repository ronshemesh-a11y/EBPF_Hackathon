#pragma once

#define MAX_FILENAME_LEN 256
#define MAX_ARGS         20
#define MAX_ARG_LEN      128
#define ARGV_BUF_SIZE    (MAX_ARGS * MAX_ARG_LEN)  /* 2560 */
#define TTY_LEN          64

/*
 * Minimal execve event: the resolved binary, the argument vector, and the
 * controlling terminal name ("" if none — used by --tty-only to drop ttyless
 * daemon/IDE/cron noise). Built directly in the ring buffer (exceeds the
 * 512-byte BPF stack limit).
 */
struct event {
	char  filename[MAX_FILENAME_LEN];
	char  argv_buf[ARGV_BUF_SIZE];
	__u32 args_count;
	char  tty[TTY_LEN];
};

#pragma once

#define MAX_FILENAME_LEN 256
#define MAX_ARGS         20
#define MAX_ARG_LEN      128
#define ARGV_BUF_SIZE    (MAX_ARGS * MAX_ARG_LEN)  /* 2560 */

/*
 * Minimal execve event: just the resolved binary and the argument vector.
 * Built directly in the ring buffer (exceeds the 512-byte BPF stack limit).
 */
struct event {
	char  filename[MAX_FILENAME_LEN];
	char  argv_buf[ARGV_BUF_SIZE];
	__u32 args_count;
};

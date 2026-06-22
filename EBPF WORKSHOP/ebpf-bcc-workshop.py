#!/usr/bin/python3

import socket
import struct
from bcc import BPF

prog = r"""
#include <linux/sched.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include <net/inet_sock.h>

BPF_PERF_OUTPUT(proc_events);
BPF_PERF_OUTPUT(file_events);

struct file_data_t {
    u32 pid;
    u64 ts;
    char path[128];
};

#define MAX_ARGS 10
#define ARG_SIZE 64

struct proc_data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
    u32 argc;
    // Flat buffer of MAX_ARGS slots, ARG_SIZE bytes each. A 2D array
    // (char[MAX_ARGS][ARG_SIZE]) is not understood by BCC's ctypes codegen.
    // Use unsigned char (not char): a ctypes c_char array is auto-truncated at
    // the first NUL on attribute access, which would drop every arg after the
    // first. unsigned char maps to c_ubyte, so bytes() returns the full buffer.
    unsigned char args[MAX_ARGS * ARG_SIZE];
};

// proc_data_t is too large for the BPF stack (512 byte limit), so use a
// per-CPU array as scratch space to build the event.
BPF_PERCPU_ARRAY(proc_scratch, struct proc_data_t, 1);

struct sys_enter_openat_args
{
    /* TODO: IMPLEMENT COMPLETE STRUCT HERE */
    unsigned long long common_tp_fields;
    int syscall_nr;
    int pad;
    int dfd;
    const char *filename;
    int flags;
    umode_t mode;
};

int sys_enter_openat(struct sys_enter_openat_args *ctx)
{
    /* TODO: IMPLEMENT HOOK HERE */
    struct file_data_t data = {};
    
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    
    bpf_probe_read_user_str(data.path, sizeof(data.path), ctx->filename);
    
    file_events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

struct sys_enter_execve_args
{
    unsigned long long common_tp_fields;
    int syscall_nr;
    char *filename;
    char **argv;
    char **envp;
};

int sys_enter_execve(struct sys_enter_execve_args *ctx)
{
    u32 zero = 0;
    struct proc_data_t *data = proc_scratch.lookup(&zero);
    if (!data)
        return 0;

    data->pid = bpf_get_current_pid_tgid();
    data->ts = bpf_ktime_get_ns();
    data->argc = 0;

    // bpf_trace_printk("Process: %s", ctx->filename);
    // filename and the argv strings live in user space, so use the *_user
    // helpers. On ARM64 the generic bpf_probe_read* helpers read via the
    // kernel-address path and only resolve user pointers by luck, which shows
    // up as intermittently empty comm/args.
    bpf_probe_read_user_str(data->comm, sizeof(data->comm), (void *)(ctx->filename));

    // argv is a NULL-terminated array of user-space char pointers. Walk it,
    // reading each pointer and then the string it points at into its own slot.
    // NOTE: copy ctx->argv into a local first. Indexing ctx->argv[i] directly
    // makes BCC's rewriter inject an implicit probe_read, so &ctx->argv[i] would
    // be the address of a stack temporary instead of the real user pointer.
    const char *const *argv = (const char *const *)(ctx->argv);
    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
        if (argp == NULL)
            break;
        bpf_probe_read_user_str(&data->args[i * ARG_SIZE], ARG_SIZE, argp);
        data->argc = i + 1;
    }

    proc_events.perf_submit(ctx, data, sizeof(*data));

    return 0;
}
"""

ARG_SIZE = 64  # must match ARG_SIZE in the BPF program

def handle_proc_event(cpu, data, size):
    output = b["proc_events"].event(data)
    raw = bytes(output.args)
    args = []
    for i in range(output.argc):
        chunk = raw[i * ARG_SIZE:(i + 1) * ARG_SIZE]
        args.append(chunk.split(b'\x00', 1)[0].decode('utf-8', 'replace'))
    print("%-18d %-16s %-6d %s" %
        (output.ts, output.comm.decode('utf-8', 'replace'),
         output.pid, ' '.join(args)))

def handle_file_event(cpu, data, size):
    output = b["file_events"].event(data)
    print("############## %-18d %-16s %-6d" %
        (output.ts, output.path.decode('utf-8', 'replace'), output.pid))

def main():
    execve_event_name = b.get_syscall_fnname("execve")
    open_event_name = b.get_syscall_fnname("openat")

    print(execve_event_name)
    print(open_event_name)

    b.attach_tracepoint(tp="syscalls:sys_enter_openat", fn_name="sys_enter_openat")
    b.attach_tracepoint(tp="syscalls:sys_enter_execve", fn_name="sys_enter_execve")

    # b.trace_print()

    # Open perf "events" buffer
    b["proc_events"].open_perf_buffer(handle_proc_event)
    b["file_events"].open_perf_buffer(handle_file_event)

    print("%-18s %-16s %-6s" % ("TIME(ns)", "COMM/PATH", "PID"))

    while 1:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            print()
            exit()

if __name__ == "__main__":
    # Needs to be globally accessible for the handler to access it
    b = BPF(text=prog)

    main()
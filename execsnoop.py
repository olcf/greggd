#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# execsnoop Trace new processes via exec() syscalls.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# This currently will print up to a maximum of 19 arguments, plus the process
# name, so 20 fields in total (MAXARG).
#
# This won't catch all new processes: an application may fork() but not exec().
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 07-Feb-2016   Brendan Gregg   Created this.
# 07-Nov-2019   Jesse Hanley    Modified for collector daemon

from __future__ import print_function
from bcc import BPF
from bcc.utils import ArgString, printb
import bcc.utils as utils
import argparse
import ctypes as ct
import re
import time
from collections import defaultdict
import threading
import json
import socket
import sys

#parser.add_argument("-x", "--fails", action="store_true",
#    help="include failed exec()s")
#parser.add_argument("-q", "--quote", action="store_true",
#    help="Add quotemarks (\") around arguments."
#    )
#parser.add_argument("-n", "--name",
#    type=ArgString,
#    help="only print commands matching this name (regex), any arg")
#parser.add_argument("-l", "--line",
#    type=ArgString,
#    help="only print commands where arg contains this line (regex)")
#parser.add_argument("--max-args", default="20",
#    help="maximum number of arguments parsed and displayed, defaults to 20")
#parser.add_argument("--ebpf", action="store_true",
#    help=argparse.SUPPRESS)
#args = parser.parse_args()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define ARGSIZE  128

enum event_type {
    EVENT_ARG,
    EVENT_RET,
};

struct data_t {
    u32 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u32 ppid; // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
    u32 uid;
    char comm[TASK_COMM_LEN];
    enum event_type type;
    char argv[ARGSIZE];
    int retval;
};

BPF_PERF_OUTPUT(events);

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    bpf_probe_read(data->argv, sizeof(data->argv), ptr);
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}

static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    const char *argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    // create data here and pass to submit_arg to save stack space (#555)
    struct data_t data = {};
    struct task_struct *task;

    data.pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the get_ppid function as a fallback in those cases. (#1883)
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_ARG;

    __submit_arg(ctx, (void *)filename, &data);

    // skip first arg, as we submitted filename
    #pragma unroll
    for (int i = 1; i < 20; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], &data) == 0)
             goto out;
    }

    // handle truncated argument list
    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, &data);
out:
    return 0;
}

int do_ret_sys_execve(struct pt_regs *ctx)
{
    struct data_t data = {};
    struct task_struct *task;

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();

    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the get_ppid function as a fallback in those cases. (#1883)
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_RET;
    data.retval = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

## initialize BPF
#b = BPF(text=bpf_text)
#execve_fnname = b.get_syscall_fnname("execve")
#b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
#b.attach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")

#print("%-16s %-6s %-6s %3s %s" % ("PCOMM", "PID", "PPID", "RET", "ARGS"))

TASK_COMM_LEN = 16      # linux/sched.h
ARGSIZE = 128           # should match #define in C above

class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("ppid", ct.c_uint),
        ("uid", ct.c_uint32),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("type", ct.c_int),
        ("argv", ct.c_char * ARGSIZE),
        ("retval", ct.c_int),
    ]

class EventType(object):
    EVENT_ARG = 0
    EVENT_RET = 1

#start_ts = time.time()
argv = defaultdict(list)

sock = None

# process event
def collect(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents

    if event.type == EventType.EVENT_ARG:
        argv[event.pid].append(event.argv)
    elif event.type == EventType.EVENT_RET:
        argv[event.pid] = [
            "\"" + arg.replace("\"", "\\\"") + "\""
            for arg in argv[event.pid]
        ]

        ppid = event.ppid if event.ppid > 0 else -1
        #ppid = b"%d" % ppid if ppid > 0 else b"?"
        argv_text = b' '.join(argv[event.pid]).replace(b'\n', b'\\n')
        #printb(b"%-16s %-6d %-6s %3d %s" % (event.comm, event.pid,
        #       ppid, event.retval, argv_text))
        bpfinfo = dict()
        bpfinfo['name'] = 'bpf'
        bpfinfo['fields'] = dict()
        bpfinfo['timestamp'] = int(time.time())
        bpfinfo['tags'] = dict()
        bpfinfo['tags']['sensor'] = 'execsnoop'
        bpfinfo['tags']['ppid'] = ppid
        bpfinfo['tags']['pid'] = int(event.pid)
        bpfinfo['tags']['uid'] = int(event.uid)
        #bpfinfo['tags']['fname'] = fname
        bpfinfo['tags']['process'] = event.comm
        bpfinfo['fields']['retval'] = event.retval
        bpfinfo['fields']['argv_text'] =  b' '.join(argv[event.pid]).replace(b'\n', b'\\n')
        with threading.Lock():
            sock.sendall("{0}\n".format(json.dumps(bpfinfo)))
        try:
            del(argv[event.pid])
        except Exception:
            pass

def main():
    global sock
    ## initialize BPF
    b = BPF(text=bpf_text)
    execve_fnname = b.get_syscall_fnname("execve")
    with threading.Lock():
        b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
        b.attach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect('/var/run/telegraf.sock')
    except socket.error, msg:
        print(msg)
        sys.exit(1)
    b["events"].open_perf_buffer(collect, page_cnt=64)
    ticker = threading.Event()
    while not ticker.wait(5):
        b.perf_buffer_poll()


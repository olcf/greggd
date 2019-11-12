#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# opensnoop Trace open() syscalls.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: opensnoop [-h] [-T] [-x] [-p PID] [-d DURATION] [-t TID] [-n NAME]
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 17-Sep-2015   Brendan Gregg   Created this.
# 29-Apr-2016   Allan McAleavy  Updated for BPF_PERF_OUTPUT.
# 08-Oct-2016   Dina Goldshtein Support filtering by PID and TID.
# 28-Dec-2018   Tim Douglas     Print flags argument, enable filtering
# 06-Jan-2019   Takuma Kume     Support filtering by UID
# 06-Nov-2019   Jesse Hanley    Modified for collector daemon

from __future__ import print_function
from bcc import ArgString, BPF
from bcc.utils import printb
import argparse
import ctypes as ct
from datetime import datetime, timedelta
import os
import threading
import time
import socket
import sys
import json

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>

struct val_t {
    u64 id;
    char comm[TASK_COMM_LEN];
    const char *fname;
    int flags; // EXTENDED_STRUCT_MEMBER
};

struct data_t {
    u64 id;
    u64 ts;
    u32 uid;
    int ret;
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
    int flags; // EXTENDED_STRUCT_MEMBER
};

BPF_HASH(infotmp, u64, struct val_t);
BPF_PERF_OUTPUT(events);

int trace_entry(struct pt_regs *ctx, int dfd, const char __user *filename, int flags)
{
    struct val_t val = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part
    u32 uid = bpf_get_current_uid_gid();

    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        val.id = id;
        val.fname = filename;
        val.flags = flags; // EXTENDED_STRUCT_MEMBER
        infotmp.update(&id, &val);
    }

    return 0;
};

int trace_return(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp;
    struct data_t data = {};

    u64 tsp = bpf_ktime_get_ns();

    valp = infotmp.lookup(&id);
    if (valp == 0) {
        // missed entry
        return 0;
    }
    bpf_probe_read(&data.comm, sizeof(data.comm), valp->comm);
    bpf_probe_read(&data.fname, sizeof(data.fname), (void *)valp->fname);
    data.id = valp->id;
    data.ts = tsp / 1000;
    data.uid = bpf_get_current_uid_gid();
    data.flags = valp->flags; // EXTENDED_STRUCT_MEMBER
    data.ret = PT_REGS_RC(ctx);

    events.perf_submit(ctx, &data, sizeof(data));
    infotmp.delete(&id);

    return 0;
}
"""

sock = None

TASK_COMM_LEN = 16    # linux/sched.h
NAME_MAX = 255        # linux/limits.h

class Data(ct.Structure):
    _fields_ = [
        ("id", ct.c_ulonglong),
        ("ts", ct.c_ulonglong),
        ("uid", ct.c_uint32),
        ("ret", ct.c_int),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("fname", ct.c_char * NAME_MAX),
        ("flags", ct.c_int),
    ]

# process event
def collect(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents

    # split return value into FD and errno columns
    if event.ret >= 0:
        fd_s = event.ret
        err = 0
    else:
        fd_s = -1
        err = - event.ret

    fname = event.fname
    if fname.startswith('/proc/'):
        return
    bpfinfo = dict()
    bpfinfo['name'] = 'bpf'
    bpfinfo['fields'] = dict()
    bpfinfo['timestamp'] = int(time.time())
    bpfinfo['tags'] = dict()
    bpfinfo['tags']['sensor'] = 'opensnoop'
    bpfinfo['tags']['errno'] = err
    bpfinfo['tags']['pid'] = int(event.id >> 32)
    bpfinfo['tags']['uid'] = int(event.uid)
    bpfinfo['tags']['fname'] = fname
    bpfinfo['tags']['process'] = event.comm
    bpfinfo['fields']['fd'] = fd_s
    bpfinfo['fields']['flags'] = "{0:08o}".format(event.flags)
    #print(bpfinfo)
    with threading.Lock():
        sock.sendall("{0}\n".format(json.dumps(bpfinfo)))

def main():
    global sock
    # load BPF program
    b = BPF(text=bpf_text)
    with threading.Lock():
        b.attach_kprobe(event="do_sys_open", fn_name="trace_entry")
        b.attach_kretprobe(event="do_sys_open", fn_name="trace_return")

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


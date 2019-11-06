#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# biolatency    Summarize block device I/O latency as a histogram.
#       For Linux, uses BCC, eBPF.
#
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 20-Sep-2015   Brendan Gregg   Created this.
# 06-Nov-2019   Jesse Hanley    Modified for collector daemon

from __future__ import print_function
from bcc import BPF
from bcc.table import HashTable
from time import sleep, strftime
import argparse
import ctypes as ct
import socket
import sys
import os
import threading
import time

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

typedef struct disk_key {
    char disk[DISK_NAME_LEN];
    u64 slot;
} disk_key_t;
BPF_HASH(start, struct request *);
BPF_HISTOGRAM(dist, disk_key_t);

// time block I/O
int trace_req_start(struct pt_regs *ctx, struct request *req)
{
    u64 ts = bpf_ktime_get_ns();
    start.update(&req, &ts);
    return 0;
}

// output
int trace_req_done(struct pt_regs *ctx, struct request *req)
{
    u64 *tsp, delta;

    // fetch timestamp and calculate delta
    tsp = start.lookup(&req);
    if (tsp == 0) {
        return 0;   // missed issue
    }
    delta = bpf_ktime_get_ns() - *tsp;
    delta /= 1000;

    // store as histogram
    disk_key_t key = {.slot = bpf_log2l(delta)};
    void *__tmp = (void *)req->rq_disk->disk_name;
    bpf_probe_read(&key.disk, sizeof(key.disk), __tmp);
    dist.increment(key);

    start.delete(&req);
    return 0;
}
"""

def collect(bpfilter):
    bpfinfo = dict()
    bpfinfo['name'] = 'bpf'
    bpfinfo['fields'] = dict()
    bpfinfo['timestamp'] = int(time.time())
    bpfinfo['tags'] = dict()
    bpfinfo['tags']['sensor'] = 'biolatency'

    dist = bpfilter.get_table("dist")

    for key, value in dist.items():
        diskname = getattr(key, dist.Key._fields_[0][0])
        lowerend = getattr(key, dist.Key._fields_[1][0])
        bpfinfo['tags']['disk'] = str(diskname) or ""
        bpfinfo['fields']['le'] = 2**(int(lowerend) - 1)
        print(bpfinfo)
    dist.clear()

def main():
    # load BPF program
    b = BPF(text=bpf_text)
    if BPF.get_kprobe_functions(b'blk_start_request'):
        b.attach_kprobe(event="blk_start_request", fn_name="trace_req_start")
    b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_req_start")
    b.attach_kprobe(event="blk_account_io_done", fn_name="trace_req_done")
    ticker = threading.Event()
    while not ticker.wait(5):
        collect(b)


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
import json

# define BPF program
bpf_text = ""
with open('/usr/share/greggd/c/biolatency.c', 'r') as fd:
    bpf_text = fd.read()

sock = None

def collect(sock, bpfilter):
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
        with threading.Lock():
            sock.sendall("{0}\n".format(json.dumps(bpfinfo)))
    dist.clear()

def main():
    global sock
    # load BPF program
    b = BPF(text=bpf_text)
    with threading.Lock():
        if BPF.get_kprobe_functions(b'blk_start_request'):
            b.attach_kprobe(event="blk_start_request", fn_name="trace_req_start")
        b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_req_start")
        b.attach_kprobe(event="blk_account_io_done", fn_name="trace_req_done")

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect('/var/run/telegraf.sock')
    except socket.error, msg:
        print(msg)
        sys.exit(1)
    ticker = threading.Event()
    while not ticker.wait(5):
        collect(sock, b)


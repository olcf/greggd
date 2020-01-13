/*
 * Inspired by the nfsdist tool by Samuel Nair
 *
 * Copyright (c) 2020 Oak Ridge National Laboratory
 * Copyright (c) 2017 Samuel Nair
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 */

#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#define OP_NAME_LEN 8
typedef struct dist_key {
    u64 slot;
} dist_key_t;
BPF_HASH(nfsdist_start, u32);
BPF_HISTOGRAM(nfsdist_hist, dist_key_t);
// time operation
int trace_entry(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    nfsdist_start.update(&pid, &ts);
    return 0;
}
int trace_return(struct pt_regs *ctx)
{
    u64 *tsp;
    u32 pid = bpf_get_current_pid_tgid();
    // fetch timestamp and calculate delta
    tsp = nfsdist_start.lookup(&pid);
    if (tsp == 0) {
        return 0;   // missed start or filtered
    }
    // Output deltas in usecs
    u64 delta = (bpf_ktime_get_ns() - *tsp) / 1000;
    // Delete old key
    nfsdist_start.delete(&pid);
    // store as histogram
    dist_key_t key;
    key.slot = bpf_log2l(delta);
    nfsdist_hist.increment(key);
    return 0;
}

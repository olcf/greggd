/*
 * Inspired by the biolatency tool by Brendan Gregg
 *
 * Copyright (c) 2020 Oak Ridge National Laboratory
 * Copyright (c) 2015 Brendan Gregg.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 */

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

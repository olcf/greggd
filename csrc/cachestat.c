/*
 * Inspired by the cachestat tool by Brendan Gregg
 *
 * Copyright (c) 2020 Oak Ridge National Laboratory
 * Copyright (c) 2016 Allan McAleavy.
 * Copyright (c) 2015 Brendan Gregg.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 */

#include <uapi/linux/ptrace.h>
struct key_t {
    u64 ip;
};

BPF_HASH(dist, struct key_t);

int do_count(struct pt_regs *ctx) {
    struct key_t key = {};
    u64 ip;

    key.ip = PT_REGS_IP(ctx);
    dist.increment(key); // update counter
    return 0;
}


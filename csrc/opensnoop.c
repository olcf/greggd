/*
 * Inspired by the opensnoop tool by Brendan Gregg
 *
 * Copyright (c) 2020 Oak Ridge National Laboratory
 * Copyright (c) 2015 Brendan Gregg.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 */

#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>

struct val_t {
    u64 id;
    char comm[TASK_COMM_LEN];
    const char * fname;
    int flags; // EXTENDED_STRUCT_MEMBER
};

struct data_t {
    u64 id;
    // u64 ts; // not currently trustworthy
    u32 pid;
    u32 uid;
    int ret;
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
    int flags; // EXTENDED_STRUCT_MEMBER
};

BPF_HASH(infotmp, u64, struct val_t);
BPF_PERF_OUTPUT(opensnoop);

int trace_entry(struct pt_regs *ctx, int dfd, const char __user *filename, int flags)
{
    struct val_t val = {};
    u64 id = bpf_get_current_pid_tgid();
    //u32 pid = id >> 32; // PID is higher part
    //u32 tid = id;       // Cast and get the lower part
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

    //u64 tsp = bpf_ktime_get_ns();

    valp = infotmp.lookup(&id);
    if (valp == 0) {
        // missed entry
        return 0;
    }
    bpf_probe_read_str(&data.comm, sizeof(valp->comm), valp->comm);
    bpf_probe_read_str(&data.fname, NAME_MAX, valp->fname);
    data.id = valp->id;
    data.pid = data.id >> 32; // Take higher part
    //data.ts = tsp;
    data.uid = bpf_get_current_uid_gid();
    data.flags = valp->flags; // EXTENDED_STRUCT_MEMBER
    data.ret = PT_REGS_RC(ctx);

    opensnoop.perf_submit(ctx, &data, sizeof(data));
    infotmp.delete(&id);

    return 0;
}

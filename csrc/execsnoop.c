/*
 * Inspired by the execsnoop tool by Brendan Gregg
 *
 * Copyright (c) 2020 Oak Ridge National Laboratory
 * Copyright (c) 2016 Netflix, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/nsproxy.h>
#include <linux/mm_types.h>

#define MAX_ARGS 12
#define ARGSIZE  32

struct data_t {
    u32 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u32 ppid; // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
    u32 uid;
    char comm[TASK_COMM_LEN];
    char env[MAX_ARGS][ARGSIZE];
    char argv[MAX_ARGS][ARGSIZE];
    int rc;
    u64 span_us;
};

BPF_PERF_OUTPUT(execs);
BPF_PERCPU_ARRAY(argtmp, struct data_t, 1);
BPF_HASH(arginfo, u64, struct data_t);

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    int zero = 0;
    u64 id = bpf_get_current_pid_tgid();

    struct task_struct *task;
    struct data_t* data = argtmp.lookup(&zero);
    if (!data)
        return 0;

    memset(data, 0, sizeof(struct data_t));

    data->span_us = bpf_ktime_get_ns(); // set to current time. Updated in return call
    data->pid = bpf_get_current_pid_tgid() >> 32; // compiler should replace inline; no need to use $id
    data->uid = bpf_get_current_uid_gid();

    task = (struct task_struct *)bpf_get_current_task();

    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the get_ppid function as a fallback in those cases. (#1883)
    //data.ppid = task->real_parent->tgid;
    data->ppid = task->real_parent->tgid;

    const char *argp = NULL;
    int max = sizeof(data->argv[0]) - 1;

    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
      argp = NULL;
      bpf_probe_read_str(&argp, sizeof(argp), (void *)&__argv[i]);
      if (argp)
      {
        bpf_probe_read(&(data->argv[i]), max, argp);
      } else {
        goto arg_out;
      }
    }

arg_out:;

    // Get max size of what env we can return
    const char *envp= NULL;
    int env_max = sizeof(data->env[0]) - 1;

    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
      envp = NULL;
      bpf_probe_read_str(&envp, sizeof(envp), (void *)&__envp[i]);
      if (envp)
      {
        bpf_probe_read(&(data->env[i]), max, envp);
      } else {
        goto env_out;
      }
    }

env_out:;

    if (bpf_get_current_comm(&data->comm, sizeof(data->comm)) == 0) {
        data->rc = 0;
    }

    arginfo.update(&id, data);
    return 0;
}

int do_ret_sys_execve(struct pt_regs *ctx)
{
    int zero = 0;
    u64 id = bpf_get_current_pid_tgid();
    struct data_t* data = arginfo.lookup(&id);
    if (!data)
        return 0;

    data->span_us = (bpf_ktime_get_ns() - data->span_us);
    data->rc = PT_REGS_RC(ctx);
    execs.perf_submit(ctx, data, sizeof(struct data_t));
    arginfo.delete(&id);

    return 0;
}

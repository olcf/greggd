#include <uapi/linux/ptrace.h>
#include <net/udp.h>
#include <net/sock.h>

struct event_data_t {
  u32 pid;
  u32 saddr;
  u32 daddr;
  u16 sport;
  u16 dport;
  u64 tx_b;
  u64 rx_b;
  char comm[TASK_COMM_LEN];
  u32 uid;
};

BPF_PERF_OUTPUT(udp_sockets);

// Populate event_data_t from ctx and socket info
static void build_udp_event(struct pt_regs *ctx, struct sock *sk, struct event_data_t *ed) {
    // Create pid, uid, comm from ctx
    ed->pid = bpf_get_current_pid_tgid() >> 32;
    ed->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&ed->comm, sizeof(ed->comm));

    // Create port and addr info from sock
    // lport is either used in a filter here, or later
    u16 sport = sk->__sk_common.skc_num;
    // destination port, switched to host byte order
    //dport = (dport >> 8) | ((dport << 8) & 0x00FF00);
    u16 dport = sk->__sk_common.skc_dport;
    dport = ntohs(dport);

    // Load data into struct
    ed->sport = sport;
    ed->dport = dport;
    ed->saddr = sk->__sk_common.skc_rcv_saddr;
    ed->daddr = sk->__sk_common.skc_daddr;
}

int syscall__udp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len) {

    struct event_data_t edata;
    // Set 0 padding
    __builtin_memset(&edata, 0, sizeof(edata));

    // Set byte count from packet
    edata.tx_b = (u64) len;
    edata.rx_b = 0;

    // Populate output data
    build_udp_event(ctx, sk, &edata);

    udp_sockets.perf_submit(ctx, &edata, sizeof(edata));
    return 0;
}

int syscall__udp_recvmsg (struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len, int noblock, int flags, int *addr_len) {

    struct event_data_t edata;
    // Set 0 padding
    __builtin_memset(&edata, 0, sizeof(edata));

    // Set byte count from packet
    edata.tx_b = 0;
    edata.rx_b = (u64) len;

    // Populate output data
    build_udp_event(ctx, sk, &edata);

    udp_sockets.perf_submit(ctx, &edata, sizeof(edata));
    return 0;
}

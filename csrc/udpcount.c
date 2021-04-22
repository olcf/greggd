#include <uapi/linux/ptrace.h>
#include <net/udp.h>
#include <net/sock.h>

struct event_data_t {
  u32 pid;
  u32 saddr;
  u32 daddr;
  u16 sport;
  u16 dport;
  u32 tx_b;
  u32 rx_b;
  u64 span_us;
  char comm[TASK_COMM_LEN];
  u64 events;
  u32 uid;
};

BPF_PERF_OUTPUT(udp_sockets);

struct sendrecv_t {
  u32 tx_b;
  u32 rx_b;
  u64 events;
};
BPF_HASH(socket_span, struct sock *, u64);
BPF_HASH(socket_data, struct sock *, struct sendrecv_t);

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
    //dport = ntohs(dport);
    dport = (dport >> 8) | ((dport << 8) & 0x00FF00);

    // Load data into struct
    ed->sport = sport;
    ed->dport = dport;
    ed->saddr = sk->__sk_common.skc_rcv_saddr;
    ed->daddr = sk->__sk_common.skc_daddr;
}

int syscall__udp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len) {

    // Look up current socket data, add rx_b, update

    struct sendrecv_t * srp = socket_data.lookup(&sk);
    // If missed create, init now
    struct sendrecv_t sr = {.tx_b = 0, .rx_b = 0, .events = 0};
    if (srp != 0) {
      sr = *srp;
    }
    sr.tx_b += (u32) len;
    sr.events += 1;
    socket_data.update(&sk, &sr);

    return 0;
}

int syscall__udp_recvmsg (struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len, int noblock, int flags, int *addr_len) {


    // Look up current socket data, add rx_b, update

    struct sendrecv_t * srp = socket_data.lookup(&sk);
    // If missed create, init now
    struct sendrecv_t sr = {.tx_b = 0, .rx_b = 0, .events = 0};
    if (srp != 0) {
      sr = *srp;
    }
    sr.rx_b += (u32) len;
    sr.events += 1;
    socket_data.update(&sk, &sr);

    return 0;
}

// Capture sock creation time, init empty socket data
int syscall__ip4_datagram_connect(struct pt_regs *ctx, struct sock *sk, struct sockaddr *uaddr, int addr_len) {
    // Save start time
    u64 ts = bpf_ktime_get_ns();
    socket_span.update(&sk, &ts);
    // Init socket data counter
    struct sendrecv_t sr = {.tx_b = 0, .rx_b = 0, .events = 0};
    socket_data.update(&sk, &sr);
    return 0;
}

// Calculate span, sav
int syscall__udp_destroy_sock(struct pt_regs *ctx, struct sock *sk) {
    struct event_data_t edata;
    // Set 0 padding
    __builtin_memset(&edata, 0, sizeof(edata));

    // Lookup values we need
    u64 *tsp, delta_us;
    struct sendrecv_t *srp;
    tsp = socket_span.lookup(&sk);
    srp = socket_data.lookup(&sk);
    // Check if we missed the socket creation. Exit if so
    if (tsp == 0) || (srp == 0) goto destroy_end;

    // calculate lifespan
    delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
    edata.span_us = delta_us;
    // calculate data sent
    edata.tx_b = srp->tx_b;
    edata.rx_b = srp->rx_b;
    edata.events = srp->events;

    // Load comm, port, addrs into struct
    build_udp_event(ctx, sk, &edata);

    // Output
    udp_sockets.perf_submit(ctx, &edata, sizeof(edata));

destory_end:;
    socket_data.delete(&sk);
    socket_span.delete(&sk);
    return 0;
}

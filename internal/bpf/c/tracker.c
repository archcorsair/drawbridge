// SPDX-License-Identifier: Apache-2.0
// drawbridge listener tracker — Phase 2.
//
// fexit/fentry hooks that keep guest_ports current from inside the kernel
// (near-zero window between a listener appearing and loopback arbitration
// seeing it) and emit ringbuf events for the agent to forward to the Mac.
//
// Hook choices (see docs/HANDOFF.md "sharp edges"):
// - TCP add:  fexit/inet_csk_listen_start — fires only on the actual
//   not-LISTEN → LISTEN transition (fexit/inet_listen would double-count a
//   re-listen that merely updates backlog).
// - TCP del:  fentry/inet_csk_listen_stop — listener-specific; inet_unhash
//   is shared with established-connection teardown. The key is recovered
//   from sk_keys, not the socket (see that map's comment).
// - UDP add:  fexit/udp_{v4,v6}_get_port — success means the socket owns
//   the port (covers ephemeral bind(0): skc_num holds the chosen port).
//   Every bound UDP socket is reachable, so clients count too; that is
//   correct for loopback arbitration and harmless for mirroring (the agent
//   only mirrors wildcard/loopback binds, and Phase 2 mirrors TCP only).
// - UDP del:  fentry/udp_lib_unhash.
//
// guest_ports values are refcounts: SO_REUSEPORT groups and dual-family
// binds produce multiple listeners per key; events fire only on 0<->1.
//
// Uses minimal CO-RE struct stubs instead of a full vmlinux.h dump —
// members are relocated by name via BTF, so only the fields read here
// need to exist.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual BSD/GPL";

#define AF_INET   2
#define AF_INET6  10
#define PROTO_TCP 6
#define PROTO_UDP 17

#define OP_ADD 1
#define OP_DEL 2

struct in6_addr {
	union {
		__u8 u6_addr8[16];
	} in6_u;
} __attribute__((preserve_access_index));

struct ns_common {
	unsigned int inum;
} __attribute__((preserve_access_index));

struct net {
	struct ns_common ns;
} __attribute__((preserve_access_index));

typedef struct {
	struct net *net;
} __attribute__((preserve_access_index)) possible_net_t;

struct sock_common {
	unsigned short skc_family;
	__be32 skc_rcv_saddr;
	struct in6_addr skc_v6_rcv_saddr;
	__u16 skc_num;
	possible_net_t skc_net;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
} __attribute__((preserve_access_index));

struct socket {
	struct sock *sk;
} __attribute__((preserve_access_index));

/* Must match struct port_key in loopback_gw.c byte for byte. */
struct port_key {
	__u8  proto;
	__u8  pad0;
	__u8  addr[16];
	__u16 port;
	__u8  pad1[2];
};

/* Replaced at load time with the gateway collection's map (MapReplacements)
 * so both programs arbitrate over the same state. Spec must stay ABI-equal. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct port_key);
	__type(value, __u32);
} guest_ports SEC(".maps");

/* sock pointer -> the key we added for it.
 *
 * Required for teardown, not an optimization: a socket bound with port 0
 * (ephemeral — what every `listen(":0")` and most servers do) does not get
 * SOCK_BINDPORT_LOCK, so tcp_set_state(TCP_CLOSE) calls inet_put_port() and
 * zeroes skc_num BEFORE inet_csk_listen_stop runs. The key cannot be
 * rebuilt from the socket at teardown; it must be remembered from bind time.
 * (Explicit binds keep their port, which is why this is easy to miss.)
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct port_key);
} sk_keys SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18);
} tracker_events SEC(".maps");

struct listener_event {
	__u8  op;
	__u8  proto;
	__u16 port;    /* host byte order */
	__u8  addr[16];
};

/* Force BTF emission for bpf2go -type. */
const struct listener_event *unused_listener_event __attribute__((unused));

static __always_inline int fill_key(struct port_key *k, struct sock *sk, __u8 proto)
{
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	__u16 port = BPF_CORE_READ(sk, __sk_common.skc_num);

	if (!port)
		return 0;
	__builtin_memset(k, 0, sizeof(*k));
	k->proto = proto;
	k->port = port;
	if (family == AF_INET) {
		__be32 a4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);

		k->addr[10] = 0xFF;
		k->addr[11] = 0xFF;
		__builtin_memcpy(&k->addr[12], &a4, 4);
	} else if (family == AF_INET6) {
		BPF_CORE_READ_INTO(&k->addr, sk,
				   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
	} else {
		return 0;
	}
	return 1;
}

/* drawbridge's own gateway listeners (127.0.0.2:*, fd77::2:*) are
 * infrastructure, not guest workload — never track them. */
static __always_inline int is_gateway_addr(const __u8 a[16])
{
	if (a[10] == 0xFF && a[11] == 0xFF &&
	    a[12] == 127 && a[13] == 0 && a[14] == 0 && a[15] == 2)
		return 1;
	if (a[0] == 0xFD && a[1] == 0x77 && a[15] == 2)
		return 1;
	return 0;
}

/* These hooks are kernel-global: since the OCI integration put docker in
 * the guest, they also fire for listeners inside bridged containers'
 * private netns. Those must never reach guest_ports or the Mac mirror —
 * a mirror would splice to guest loopback where nothing listens. Set by
 * LoadTracker to the agent's own netns inum; 0 disables the filter.
 * track_del needs the filter as much as track_add: its fill_key fallback
 * would otherwise let a foreign 0.0.0.0:P close decrement the refcount of
 * the host's identically-keyed entry. */
volatile const __u32 host_netns_inum;

static __always_inline int in_host_netns(struct sock *sk)
{
	if (!host_netns_inum)
		return 1;
	return BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum) == host_netns_inum;
}

static __always_inline void emit(const struct port_key *k, __u8 op)
{
	struct listener_event *ev;

	ev = bpf_ringbuf_reserve(&tracker_events, sizeof(*ev), 0);
	if (!ev)
		return; /* ring full: map state is still correct */
	ev->op = op;
	ev->proto = k->proto;
	ev->port = k->port;
	__builtin_memcpy(ev->addr, k->addr, 16);
	bpf_ringbuf_submit(ev, 0);
}

static __always_inline void track_add(struct sock *sk, __u8 proto)
{
	__u64 skp = (__u64)sk;
	struct port_key k;
	__u32 one = 1;
	__u32 *cnt;

	if (!in_host_netns(sk))
		return;
	if (!fill_key(&k, sk, proto))
		return;
	if (is_gateway_addr(k.addr))
		return;

	bpf_map_update_elem(&sk_keys, &skp, &k, BPF_ANY);

	cnt = bpf_map_lookup_elem(&guest_ports, &k);
	if (cnt) {
		__sync_fetch_and_add(cnt, 1);
		return;
	}
	bpf_map_update_elem(&guest_ports, &k, &one, BPF_ANY);
	emit(&k, OP_ADD);
}

static __always_inline void track_del(struct sock *sk, __u8 proto)
{
	__u64 skp = (__u64)sk;
	struct port_key k, *saved;
	__u32 *cnt;

	if (!in_host_netns(sk))
		return;
	saved = bpf_map_lookup_elem(&sk_keys, &skp);
	if (saved) {
		k = *saved;
		bpf_map_delete_elem(&sk_keys, &skp);
	} else if (!fill_key(&k, sk, proto)) {
		return; /* never tracked, or port already gone */
	}
	if (is_gateway_addr(k.addr))
		return;

	cnt = bpf_map_lookup_elem(&guest_ports, &k);
	if (!cnt)
		return;
	if (__sync_sub_and_fetch(cnt, 1) > 0)
		return;
	bpf_map_delete_elem(&guest_ports, &k);
	emit(&k, OP_DEL);
}

SEC("fexit/inet_csk_listen_start")
int BPF_PROG(tcp_listen_start, struct sock *sk, int ret)
{
	if (ret)
		return 0;
	track_add(sk, PROTO_TCP);
	return 0;
}

SEC("fentry/inet_csk_listen_stop")
int BPF_PROG(tcp_listen_stop, struct sock *sk)
{
	track_del(sk, PROTO_TCP);
	return 0;
}

SEC("fexit/udp_v4_get_port")
int BPF_PROG(udp4_bind, struct sock *sk, unsigned short snum, int ret)
{
	if (ret)
		return 0;
	track_add(sk, PROTO_UDP);
	return 0;
}

SEC("fexit/udp_v6_get_port")
int BPF_PROG(udp6_bind, struct sock *sk, unsigned short snum, int ret)
{
	if (ret)
		return 0;
	track_add(sk, PROTO_UDP);
	return 0;
}

SEC("fentry/udp_lib_unhash")
int BPF_PROG(udp_unbind, struct sock *sk)
{
	track_del(sk, PROTO_UDP);
	return 0;
}

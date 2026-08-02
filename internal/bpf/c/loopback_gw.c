// SPDX-License-Identifier: Apache-2.0
// drawbridge loopback gateway — Phase 1.
//
// cgroup/sock_addr programs that merge the guest's 127.0.0.1 with the Mac's
// loopback at L4. Same-port gateway scheme: a connect/sendto to 127.0.0.1:P
// that is NOT served by a guest listener but IS served by a Mac listener is
// rewritten to GATEWAY:P (127.0.0.2:P / fd77::2:P), where the drawbridge
// agent runs one proxy listener per Mac-owned port. Because only the IP is
// swapped (never the port), getpeername/recvmsg un-rewrites are stateless
// address transforms and multi-destination UDP demuxes naturally.
//
// Decision order (load-bearing, do not reorder):
//   1. dst is not exactly 127.0.0.1/::1  -> pass (gateway + everything else)
//   2. port served by guest_ports        -> pass (native VM loopback wins)
//   3. port served by mac_ports          -> rewrite IP to gateway, keep port
//   4. neither                           -> pass (fast native ECONNREFUSED)

#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual BSD/GPL";

#define LOOPBACK_V4 bpf_htonl(0x7F000001) /* 127.0.0.1 */
#define GATEWAY_V4  bpf_htonl(0x7F000002) /* 127.0.0.2 */
#define V4MAPPED_PREFIX bpf_htonl(0x0000FFFF)
#define GATEWAY_V6_0 bpf_htonl(0xFD770000) /* fd77::2 */

/* Explicit padding: hash lookups are byte-wise; implicit compiler padding
 * holes would make lookups miss nondeterministically. Zero-init all keys. */
struct port_key {
	__u8  proto;    /* IPPROTO_TCP or IPPROTO_UDP */
	__u8  pad0;
	__u8  addr[16]; /* listener bind address, IPv6 or IPv4-mapped */
	__u16 port;     /* host byte order */
	__u8  pad1[2];
};

/* Values are refcounts (the Phase 2 tracker manages guest_ports from
 * kernel side; SO_REUSEPORT groups count per-listener). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct port_key);
	__type(value, __u32);
} guest_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct port_key);
	__type(value, __u32);
} mac_ports SEC(".maps");

static __always_inline void v4_mapped(__u8 dst[16], __be32 a)
{
	__builtin_memset(dst, 0, 10);
	dst[10] = 0xFF;
	dst[11] = 0xFF;
	__builtin_memcpy(dst + 12, &a, 4);
}

static __always_inline int port_present(void *map, __u8 proto,
					const __u8 addr[16], __u16 port_h)
{
	struct port_key k = {};

	k.proto = proto;
	k.port = port_h;
	__builtin_memcpy(k.addr, addr, 16);
	return bpf_map_lookup_elem(map, &k) != NULL;
}

/* Is 127.0.0.1:P served by a listener recorded in `map`? A loopback connect
 * is served by a bind to 127.0.0.1, 0.0.0.0, or a dual-stack ::. */
static __always_inline int lb4_served(void *map, __u8 proto, __u16 port_h)
{
	__u8 a[16];

	v4_mapped(a, LOOPBACK_V4);
	if (port_present(map, proto, a, port_h))
		return 1;
	v4_mapped(a, 0);
	if (port_present(map, proto, a, port_h))
		return 1;
	__builtin_memset(a, 0, 16);
	return port_present(map, proto, a, port_h);
}

/* Is [::1]:P served? Binds to ::1 or :: count. */
static __always_inline int lb6_served(void *map, __u8 proto, __u16 port_h)
{
	__u8 a[16] = {};

	a[15] = 1;
	if (port_present(map, proto, a, port_h))
		return 1;
	a[15] = 0;
	return port_present(map, proto, a, port_h);
}

static __always_inline int sk_proto(struct bpf_sock_addr *ctx, __u8 *proto)
{
	if (ctx->protocol == IPPROTO_TCP)
		*proto = IPPROTO_TCP;
	else if (ctx->protocol == IPPROTO_UDP)
		*proto = IPPROTO_UDP;
	else
		return 0; /* ICMP etc: never intercept */
	return 1;
}

static __always_inline int handle_v4(struct bpf_sock_addr *ctx)
{
	__u8 proto;
	__u16 port_h;

	if (ctx->user_ip4 != LOOPBACK_V4)
		return 1;
	if (!sk_proto(ctx, &proto))
		return 1;
	port_h = bpf_ntohs((__u16)ctx->user_port);
	if (!port_h)
		return 1;
	if (lb4_served(&guest_ports, proto, port_h))
		return 1;
	if (lb4_served(&mac_ports, proto, port_h))
		ctx->user_ip4 = GATEWAY_V4;
	return 1;
}

SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *ctx)
{
	return handle_v4(ctx);
}

SEC("cgroup/sendmsg4")
int sendmsg4(struct bpf_sock_addr *ctx)
{
	return handle_v4(ctx);
}

SEC("cgroup/recvmsg4")
int recvmsg4(struct bpf_sock_addr *ctx)
{
	if (ctx->user_ip4 == GATEWAY_V4)
		ctx->user_ip4 = LOOPBACK_V4;
	return 1;
}

SEC("cgroup/getpeername4")
int getpeername4(struct bpf_sock_addr *ctx)
{
	if (ctx->user_ip4 == GATEWAY_V4)
		ctx->user_ip4 = LOOPBACK_V4;
	return 1;
}

/* ---- IPv6 ---- */

static __always_inline int v6_is(struct bpf_sock_addr *ctx, __be32 w0,
				 __be32 w1, __be32 w2, __be32 w3)
{
	return ctx->user_ip6[0] == w0 && ctx->user_ip6[1] == w1 &&
	       ctx->user_ip6[2] == w2 && ctx->user_ip6[3] == w3;
}

static __always_inline void v6_set(struct bpf_sock_addr *ctx, __be32 w0,
				   __be32 w1, __be32 w2, __be32 w3)
{
	ctx->user_ip6[0] = w0;
	ctx->user_ip6[1] = w1;
	ctx->user_ip6[2] = w2;
	ctx->user_ip6[3] = w3;
}

static __always_inline int handle_v6(struct bpf_sock_addr *ctx)
{
	__u8 proto;
	__u16 port_h;

	if (!sk_proto(ctx, &proto))
		return 1;
	port_h = bpf_ntohs((__u16)ctx->user_port);
	if (!port_h)
		return 1;

	/* v4-mapped ::ffff:127.0.0.1 through the v6 API */
	if (v6_is(ctx, 0, 0, V4MAPPED_PREFIX, LOOPBACK_V4)) {
		if (lb4_served(&guest_ports, proto, port_h))
			return 1;
		if (lb4_served(&mac_ports, proto, port_h))
			ctx->user_ip6[3] = GATEWAY_V4;
		return 1;
	}
	/* ::1 */
	if (v6_is(ctx, 0, 0, 0, bpf_htonl(1))) {
		if (lb6_served(&guest_ports, proto, port_h))
			return 1;
		if (lb6_served(&mac_ports, proto, port_h))
			v6_set(ctx, GATEWAY_V6_0, 0, 0, bpf_htonl(2));
		return 1;
	}
	return 1;
}

SEC("cgroup/connect6")
int connect6(struct bpf_sock_addr *ctx)
{
	return handle_v6(ctx);
}

SEC("cgroup/sendmsg6")
int sendmsg6(struct bpf_sock_addr *ctx)
{
	return handle_v6(ctx);
}

static __always_inline int unrewrite_v6(struct bpf_sock_addr *ctx)
{
	if (v6_is(ctx, GATEWAY_V6_0, 0, 0, bpf_htonl(2)))
		v6_set(ctx, 0, 0, 0, bpf_htonl(1));
	else if (v6_is(ctx, 0, 0, V4MAPPED_PREFIX, GATEWAY_V4))
		ctx->user_ip6[3] = LOOPBACK_V4;
	return 1;
}

SEC("cgroup/recvmsg6")
int recvmsg6(struct bpf_sock_addr *ctx)
{
	return unrewrite_v6(ctx);
}

SEC("cgroup/getpeername6")
int getpeername6(struct bpf_sock_addr *ctx)
{
	return unrewrite_v6(ctx);
}

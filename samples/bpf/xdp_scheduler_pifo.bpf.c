// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Freysteinn Alfredsson <freysteinn@freysteinn.com> */

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH 2
#endif

#define VLAN_VID_MASK	0x0fff /* VLAN Identifier 		*/
#define ETH_P_8021Q 	0x8100 /* 802.1Q VLAN Extended Header 	*/
#define ETH_P_8021AD	0x88A8 /* 802.1ad Service VLAN 		*/
#define ETH_P_IP	0x0800 /* Internet Protocol packet 	*/
#define ETH_P_IPV6	0x86DD /* IPv6 over bluebook 		*/

#define IPPROTO_HOPOPTS		0	/* IPv6 hop-by-hop options	*/
#define IPPROTO_DSTOPTS		60	/* IPv6 destination options	*/
#define IPPROTO_ROUTING		43	/* IPv6 routing header		*/
#define IPPROTO_MH		135	/* IPv6 mobility header		*/
#define IPPROTO_FRAGMENT	44	/* IPv6 fragmentation header	*/


/* Longest chain of IPv6 extension headers to resolve */
#ifndef IPV6_EXT_MAX_CHAIN
#define IPV6_EXT_MAX_CHAIN 6
#endif

struct collect_vlans {
	__u16 id[VLAN_MAX_DEPTH];
};

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

struct {
	__uint(type, BPF_MAP_TYPE_PIFO);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 1024);
} pifo_map SEC(".maps");


/* Helper functions */

static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		  h_proto == bpf_htons(ETH_P_8021AD));
}

/* Notice, parse_ethhdr() will skip VLAN tags, by advancing nh->pos and returns
 * next header EtherType, BUT the ethhdr pointer supplied still points to the
 * Ethernet header. Thus, caller can look at eth->h_proto to see if this was a
 * VLAN tagged packet.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh, void *data_end,
                                        struct ethhdr **ethhdr)
{
        struct ethhdr *eth = nh->pos;
        struct vlan_hdr *vlh;
        __u16 h_proto;
        int i;

        if (eth + 1 > data_end)
                return -1;

        nh->pos = eth + 1;
        *ethhdr = eth;
        vlh = nh->pos;
        h_proto = eth->h_proto;

        /* Use loop unrolling to avoid the verifier restriction on loops;
         * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
         */
        #pragma unroll
        for (i = 0; i < VLAN_MAX_DEPTH; i++) {
                if (!proto_is_vlan(h_proto))
                        break;

                if (vlh + 1 > data_end)
                        break;

                h_proto = vlh->h_vlan_encapsulated_proto;
                vlh++;
        }

        nh->pos = vlh;
        return h_proto; /* network-byte-order */
}

static __always_inline int skip_ip6hdrext(struct hdr_cursor *nh,
                                          void *data_end,
                                          __u8 next_hdr_type)
{
        for (int i = 0; i < IPV6_EXT_MAX_CHAIN; ++i) {
                struct ipv6_opt_hdr *hdr = nh->pos;

                if (hdr + 1 > data_end)
                        return -1;

                switch (next_hdr_type) {
                case IPPROTO_HOPOPTS:
                case IPPROTO_DSTOPTS:
                case IPPROTO_ROUTING:
                case IPPROTO_MH:
                        nh->pos = (char *)hdr + (hdr->hdrlen + 1) * 8;
                        next_hdr_type = hdr->nexthdr;
                        break;
                case IPPROTO_AH:
                        nh->pos = (char *)hdr + (hdr->hdrlen + 2) * 4;
                        next_hdr_type = hdr->nexthdr;
                        break;
                case IPPROTO_FRAGMENT:
                        nh->pos = (char *)hdr + 8;
                        next_hdr_type = hdr->nexthdr;
                        break;
                default:
                        /* Found a header that is not an IPv6 extension header */
                        return next_hdr_type;
                }
        }
        return -1;
}

static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct ipv6hdr **ip6hdr)
{
        struct ipv6hdr *ip6h = nh->pos;

        if (ip6h + 1 > data_end)
                return -1;

        nh->pos = ip6h + 1;
        *ip6hdr = ip6h;

        return skip_ip6hdrext(nh, data_end, ip6h->nexthdr);
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
                                       void *data_end,
                                       struct iphdr **iphdr)
{
        struct iphdr *iph = nh->pos;
        int hdrsize;

        if (iph + 1 > data_end)
                return -1;

        hdrsize = iph->ihl * 4;

        /* Variable-length IPv4 header, need to use byte-based arithmetic */
        if (nh->pos + hdrsize > data_end)
                return -1;

        nh->pos += hdrsize;
        *iphdr = iph;

        return iph->protocol;
}

/*
 * parse_udphdr: parse the udp header and return the length of the udp payload
 */
static __always_inline int parse_udphdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct udphdr **udphdr)
{
        int len;
        struct udphdr *h = nh->pos;

        if (h + 1 > data_end)
                return -1;

        nh->pos  = h + 1;
        *udphdr = h;

        len = bpf_ntohs(h->len) - sizeof(struct udphdr);
        if (len < 0)
                return -1;

        return len;
}

/* Simple PIFO strict priority */
SEC("xdp")
int enqueue_prog(struct xdp_md *xdp)
{

	void *data_end = (void *)(long)xdp->data_end;
	void *data = (void *)(long)xdp->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	int ip_type;
	struct udphdr *udphdr;
	int udp_len;
	int udp_dst_port;
	__u16 prio;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type != IPPROTO_UDP) {
			goto out;
		}
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
		if (ip_type == -1) {
			prio = ip_type;
		}
		if (ip_type != IPPROTO_UDP) {
			goto out;
		}
	} else {
		goto out;
	}

	/* Parse UDP header */
	udp_len = parse_udphdr(&nh, data_end, &udphdr);
	if (udp_len < 0) {
		goto out;
	}
	udp_dst_port = bpf_htons(udphdr->dest);

	/* Calculate scheduling priority */
	prio = 0;
	if (udp_dst_port == 8081)
		prio = 1;
	else if (udp_dst_port > 8081)
		prio = 2;

	bpf_printk("XDP PIFO scheduled with priority %d", prio);
	return bpf_redirect_map(&pifo_map, prio, 0);
out:
	bpf_printk("XDP PIFO dropped packet %d", prio);
	return XDP_DROP;
}

SEC("dequeue")
int dequeue_prog(struct dequeue_ctx *ctx)
{
	void *pkt = (void *) bpf_packet_dequeue(ctx, &pifo_map, 0);
	if (!pkt)
		return 0;
	else {
		bpf_printk("Kern DEQUEUE");
		return bpf_packet_return(ctx, pkt);
	}
}

char _license[] SEC("license") = "GPL";

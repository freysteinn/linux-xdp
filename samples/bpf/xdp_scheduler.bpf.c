// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Freysteinn Alfredsson <freysteinn@freysteinn.com> */

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>


struct {
	__uint(type, BPF_MAP_TYPE_PIFO);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 1024);
} pifo_map SEC(".maps");

/* Simple PIFO strict priority */
SEC("xdp")
int xdp_pifo(struct xdp_md *xdp)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	struct ethhdr *eth = data;
	__u16 prio;

	if (eth + 1 > data_end)
		return XDP_DROP;

	prio = bpf_ntohs(eth->h_proto);

	return bpf_redirect_map(&pifo_map, prio, 0);
}

SEC("dequeue")
int dequeue_pifo(struct dequeue_ctx *ctx)
{
	void *pkt = (void *) bpf_packet_dequeue(ctx, &pifo_map, 0);
	if (!pkt)
		return 0;
	else {
		return bpf_packet_return(ctx, pkt);
	}
}

char _license[] SEC("license") = "GPL";

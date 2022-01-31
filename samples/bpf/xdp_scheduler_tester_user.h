// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2022 Freysteinn Alfredsson <freysteinn@freysteinn.com>
 */

#ifndef XDP_SCHEDULER_TESTER_USER_H_
#define XDP_SCHEDULER_TESTER_USER_H_

#define MAX_LINE (1 << 10)
#define MAX_TOKEN (1 << 6)

struct cmd_udp_state {
	struct ipv6_udp_packet *pkt;
	size_t pkt_size;
};

union cmd_state {
	struct cmd_udp_state udp;
};

struct ipv6_udp_packet {
	struct ethhdr eth;
	struct ipv6hdr iph;
	struct udphdr udp;
	__u8 payload[64 - sizeof(struct udphdr)
		     - sizeof(struct ethhdr) - sizeof(struct ipv6hdr)];
} __packed;

struct config {
	struct {
		struct ipv6_udp_packet *pkt;
		int ifindex;
		char ifname[IFNAMSIZ];
	} global;

	union cmd_state state;
	int xdp_prog_fd;
	int dequeue_prog_fd;
	char *token;
	char line[MAX_LINE];
	int line_nr;
	int verbose;
};


typedef struct trace_cmd trace_cmd;
typedef void (*trace_fn)(void *parameter, struct config *cfg);

enum argument_type {
	at_no_argument,
	at_subcommand,
	at_integer,
	at_string,
};

typedef struct trace_cmd {
	char *command;
	trace_cmd *next;
	trace_fn init_func;
	trace_fn func;
	enum argument_type type;
} trace_cmd;


void setmac(struct config *cfg);

char *parse_elements(char *line, trace_cmd *cmd_category, struct config *cfg);
void run_file(FILE* trace_file, struct config *cfg);

void cmd_udp_eth_proto_fn(void* proto, struct config *cfg);
void cmd_udp_dst_port_fn(void* port, struct config *cfg);
void cmd_udp_dst_ip_fn(void* ip, struct config *cfg);
void cmd_udp_init_fn(void *none, struct config *cfg);
void cmd_udp_fn(void *none, struct config *cfg);

void cmd_d_udp_eth_proto_fn(void* proto, struct config *cfg);
void cmd_d_udp_dst_port_fn(void* port, struct config *cfg);
void cmd_d_udp_dst_ip_fn(void* ip, struct config *cfg);
void cmd_d_udp_init_fn(void *none, struct config *cfg);
void cmd_d_udp_fn(void *none, struct config *cfg);


#endif // XDP_SCHEDULER_TESTER_USER_H_

// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2022 Freysteinn Alfredsson <freysteinn@freysteinn.com> */

#define _GNU_SOURCE
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <linux/udp.h>
#include <assert.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <net/if.h>
#include <unistd.h>
#include <libgen.h>
#include <limits.h>
#include <getopt.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <bpf/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/libbpf.h>
#include "bpf_util.h"

#include "xdp_sample_user.h"
#include "xdp_scheduler.skel.h"
#include "xdp_scheduler_tester_user.h"


static const struct option long_options[] = {
	{"file",	required_argument,	NULL, 'f' },
	{"interface",	required_argument,	NULL, 'i' },
	{"src-mac",	required_argument,	NULL, 'm' },
	{"src-ip",	required_argument,	NULL, 'a' },
	{"src-port",	required_argument,	NULL, 'p' },
	{"verbose",	no_argument,		NULL, 'v' },
	{"help",	no_argument,		NULL, 'h' },
	{}
};


/*
 * Parser commands
 */

/* UDP commands */
trace_cmd cmd_udp_eth[] = {
	{ "proto",	NULL,	NULL,	cmd_udp_eth_proto_fn,	at_integer },
	{}
};

trace_cmd cmd_udp_dst[] = {
	{ "port",	NULL,	NULL,	cmd_udp_dst_port_fn,	at_integer },
	{ "ip",		NULL,	NULL,	cmd_udp_dst_ip_fn,	at_string },
	{}
};

trace_cmd cmd_udp_src[] = {
	{ "port",	NULL,	NULL,	NULL,	at_integer },
	{ "ip",		NULL,	NULL,	NULL,	at_string },
	{}
};

trace_cmd cmd_udp_payload[] = {
	{ "data",	NULL,	NULL,	NULL,	at_string },
	{ "length",	NULL,	NULL,	NULL,	at_integer },
	{}
};

trace_cmd cmd_udp[] = {
	{ "eth",	cmd_udp_eth,		NULL,	NULL,	at_subcommand },
	{ "dst",	cmd_udp_dst,		NULL,	NULL,	at_subcommand },
	{ "src",	cmd_udp_src,		NULL,	NULL,	at_subcommand },
	{ "payload",	cmd_udp_payload,	NULL,	NULL,	at_string },
	{}
};


/* Dequeue commands */
trace_cmd cmd_d_udp_eth[] = {
	{ "proto",	NULL,	NULL,	cmd_d_udp_eth_proto_fn,	at_integer },
	{}
};

trace_cmd cmd_d_udp_dst[] = {
	{ "port",	NULL,	NULL,	cmd_d_udp_dst_port_fn,	at_integer },
	{ "ip",		NULL,	NULL,	cmd_d_udp_dst_ip_fn,	at_string },
	{}
};

trace_cmd cmd_d_udp_src[] = {
	{ "port",	NULL,	NULL,	NULL,	at_integer },
	{ "ip",		NULL,	NULL,	NULL,	at_string },
	{}
};

trace_cmd cmd_d_udp_payload[] = {
	{ "data",	NULL,	NULL,	NULL,	at_string },
	{ "length",	NULL,	NULL,	NULL,	at_integer },
	{}
};

trace_cmd cmd_dequeue_udp[] = {
	{ "eth",	cmd_d_udp_eth,		NULL,	NULL,	at_subcommand },
	{ "dst",	cmd_d_udp_dst,		NULL,	NULL,	at_subcommand },
	{ "src",	cmd_d_udp_src,		NULL,	NULL,	at_subcommand },
	{ "payload",	cmd_d_udp_payload,	NULL,	NULL,	at_string },
	{}
};

trace_cmd cmd_dequeue[] = {
	{ "udp",	cmd_dequeue_udp,	cmd_d_udp_init_fn,	cmd_d_udp_fn,	at_subcommand },
	{}
};


/* Main commands */
trace_cmd cmd_main[] = {
	{ "udp",	cmd_udp,	cmd_udp_init_fn,	cmd_udp_fn,	at_subcommand },
	{ "dequeue",	cmd_dequeue,	NULL,			NULL,		at_subcommand },
	{}
};


static struct ipv6_udp_packet global_udp_pkt_v6 = {
	.iph.version = 6,
	.eth.h_proto = __bpf_constant_htons(ETH_P_IPV6),
	.eth.h_source = {1, 0, 0, 0, 0, 1},
	.eth.h_dest = {1, 0, 0, 0, 0, 2},
	.iph.nexthdr = IPPROTO_UDP,
	.iph.payload_len = bpf_htons(sizeof(struct ipv6_udp_packet)
				     - offsetof(struct ipv6_udp_packet, udp)),
	.iph.hop_limit = 1,
	.iph.saddr.s6_addr16 = {bpf_htons(0xfe80), 0, 0, 0, 0, 0, 0, bpf_htons(1)},
	.iph.daddr.s6_addr16 = {bpf_htons(0xfe80), 0, 0, 0, 0, 0, 0, bpf_htons(2)},
	.udp.source = bpf_htons(1),
	.udp.dest = bpf_htons(1),
	.udp.len = bpf_htons(sizeof(struct ipv6_udp_packet)
			     - offsetof(struct ipv6_udp_packet, udp)),
};


/* Get the mac address of the interface given interface name */
void setmac(struct config *cfg)
{
	struct ipv6_udp_packet *pkt = cfg->global.pkt;
	struct ifreq ifr;
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "socket failed...\n");
		exit(EXIT_FAILURE);
	}
	ifr.ifr_addr.sa_family = AF_INET;
	memcpy(&ifr.ifr_name, cfg->global.ifname, IFNAMSIZ);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		fprintf(stderr, "ioctl failed leaving...\n");
		close(fd);
		exit(EXIT_FAILURE);
	}
	for (int i = 0; i < 6 ; i++) {
		pkt->eth.h_source[i] = (__u8)ifr.ifr_hwaddr.sa_data[i];
	}
	close(fd);
}

static __be16 calc_udp_cksum(const struct ipv6_udp_packet *pkt)
{
	__u32 chksum = pkt->iph.nexthdr + bpf_ntohs(pkt->iph.payload_len);
	int i;

	for (i = 0; i < 8; i++) {
		chksum += bpf_ntohs(pkt->iph.saddr.s6_addr16[i]);
		chksum += bpf_ntohs(pkt->iph.daddr.s6_addr16[i]);
	}
	chksum += bpf_ntohs(pkt->udp.source);
	chksum += bpf_ntohs(pkt->udp.dest);
	chksum += bpf_ntohs(pkt->udp.len);

	while (chksum >> 16)
		chksum = (chksum & 0xFFFF) + (chksum >> 16);
	return bpf_htons(~chksum);
}


/* UDP commands */
void cmd_udp_eth_proto_fn(void *parameter, struct config *cfg)
{
	int proto = *((int *) parameter);
	struct ipv6_udp_packet *pkt = cfg->state.udp.pkt;
	if (proto < 0 || proto > 65535) {
		fprintf(stderr, "%s:%d: ", cfg->line, cfg->line_nr);
		fprintf(stderr, "Ethernet protocol out of bounds %d\n", proto);
		exit(EXIT_FAILURE);
	}
	pkt->eth.h_proto = __bpf_htons(proto);
}

void cmd_udp_dst_port_fn(void *parameter, struct config *cfg)
{
	int port = *((int *) parameter);
	struct ipv6_udp_packet *pkt = cfg->state.udp.pkt;
	if (port < 0 || port > 65535) {
		fprintf(stderr, "%s:%d: ", cfg->line, cfg->line_nr);
		fprintf(stderr, "UDP port out of bounds %d\n", port);
		exit(EXIT_FAILURE);
	}
	pkt->udp.dest = port;
}

void cmd_udp_dst_ip_fn(void *parameter, struct config *cfg)
{
	char *ip = (char *) parameter;
	if (!inet_pton(AF_INET6, ip, &cfg->state.udp.pkt->iph.daddr)) {
		fprintf(stderr, "%s:%d: ", cfg->line, cfg->line_nr);
		fprintf(stderr, "Failed to set dst IPv6 address to %s\n", ip);
		exit(EXIT_FAILURE);
	}
}

void cmd_udp_init_fn(void *none, struct config *cfg)
{
	struct ipv6_udp_packet *pkt = malloc(sizeof(*pkt));
	memcpy(pkt, cfg->global.pkt, sizeof(*pkt));
	cfg->state.udp.pkt = pkt,
	cfg->state.udp.pkt_size = sizeof(*pkt);
}

void cmd_udp_fn(void *none, struct config *cfg)
{
	int err;
	struct ipv6_udp_packet *pkt = cfg->state.udp.pkt;
	pkt->udp.check = calc_udp_cksum(pkt);
	struct xdp_md ctx_in = {
		.data_end = cfg->state.udp.pkt_size,
	};
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
			    .data_in = pkt,
			    .data_size_in = cfg->state.udp.pkt_size,
			    .ctx_in = &ctx_in,
			    .ctx_size_in = sizeof(ctx_in),
			    .repeat = 1,
			    .flags = BPF_F_TEST_XDP_DO_REDIRECT,
		);
	ctx_in.data_end = ctx_in.data + cfg->state.udp.pkt_size;
	err = bpf_prog_test_run_opts(cfg->xdp_prog_fd, &opts);
	if (err) {
		fprintf(stderr, "%s:%d: ", cfg->line, cfg->line_nr);
		fprintf(stderr, "Failed to run XDP hook\n");
		exit(EXIT_FAILURE);
	}
	free(cfg->state.udp.pkt);
	cfg->state.udp.pkt_size = 0;
}

/* Dequeue commands */
void cmd_d_udp_eth_proto_fn(void *parameter, struct config *cfg)
{
	int proto = *((int *) parameter);
	struct ipv6_udp_packet *pkt = cfg->state.udp.pkt;
	__be16 pkt_proto = __bpf_ntohs(pkt->eth.h_proto);
	if (pkt_proto != proto) {
		fprintf(stderr, "%s:%d: ", cfg->line, cfg->line_nr);
		fprintf(stderr, "Expected ethernet protocol %d but found %hd\n",
			proto, pkt_proto);
		exit(EXIT_FAILURE);
	}
}

void cmd_d_udp_dst_port_fn(void *parameter, struct config *cfg)
{
	int port = *((int *) parameter);
	struct ipv6_udp_packet *pkt = cfg->state.udp.pkt;
	if (pkt->udp.dest != port) {
		fprintf(stderr, "%s:%d: ", cfg->line, cfg->line_nr);
		fprintf(stderr, "Expected UDP destination port %d but found %hd\n",
			port, pkt->udp.dest);
		exit(EXIT_FAILURE);
	}
}

void cmd_d_udp_dst_ip_fn(void *parameter, struct config *cfg)
{
	char *ip = (char *) parameter;
	struct in6_addr dst_ip;
	char pkt_dst_ip[INET6_ADDRSTRLEN + 1];
	struct ipv6_udp_packet *pkt = cfg->state.udp.pkt;
	if (!inet_pton(AF_INET6, ip, (char *) &dst_ip)) {
		fprintf(stderr, "%s:%d: ", cfg->line, cfg->line_nr);
		fprintf(stderr, "Failed to parse IPv6 address %s\n", ip);
		exit(EXIT_FAILURE);
	}

	if (memcmp(&pkt->iph.daddr, &dst_ip, sizeof(struct in6_addr))) {
		inet_ntop(AF_INET6, &pkt->iph.daddr, (char *) &pkt_dst_ip,
			  sizeof(pkt_dst_ip));
		fprintf(stderr, "%s:%d: ", cfg->line, cfg->line_nr);
		fprintf(stderr, "Expected IPv6 address %s but found %s\n",
			ip, pkt_dst_ip);
		exit(EXIT_FAILURE);
	}
}

void cmd_d_udp_init_fn(void *parameter, struct config *cfg)
{
	int err;
	struct ipv6_udp_packet *pkt = calloc(sizeof(*pkt), 1);
	cfg->state.udp.pkt = pkt;
	cfg->state.udp.pkt_size = sizeof(*pkt);
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
			    .data_out = pkt,
			    .data_size_out = sizeof(*pkt),
			    .repeat = 1,
		);

	err = bpf_prog_test_run_opts(cfg->dequeue_prog_fd, &opts);
	if (err) {
		fprintf(stderr, "%s:%d: ", cfg->line, cfg->line_nr);
		fprintf(stderr, "Failed to run DEQUEUE hook\n");
		exit(EXIT_FAILURE);
	}

	if (!cfg->verbose)
		return;
	printf("Payload: ");
	for (int i = 0; i < sizeof(*pkt); i++) {
		printf("%02x ", ((unsigned char *) pkt)[i]);
	}
	printf("\n");
}

void cmd_d_udp_fn(void *none, struct config *cfg)
{
	free(cfg->state.udp.pkt);
}


/* Parser  */
char *parse_elements(char *line, trace_cmd *cmd_category, struct config *cfg)
{
	char *token = NULL;
	trace_cmd *cmd;
	int has_unidentified = true;
	while ((token = strtok(line, " \t\n"))) {
		cfg->token = token;
		if (line)
			line = NULL;
		cmd = cmd_category;
		has_unidentified = true;
		do {
			int int_value = 0;
			char str_value[MAX_LINE] = {0};
			void *parameter = NULL;
			char token_format[MAX_TOKEN + 1];
			if (!cmd->command)
				break;
			strncpy(token_format, cmd->command, MAX_TOKEN - 1);
			switch (cmd->type) {
			case at_subcommand:
				if (strcmp(cmd->command, token))
					continue;

				if (cmd->init_func)
					cmd->init_func(NULL, cfg);
				if (cmd->next)
					token = parse_elements(NULL, cmd->next, cfg);
				if (cmd->func)
					cmd->func(parameter, cfg);

				if (!token)
					return NULL;
				cmd = cmd_category;
				continue;
			case at_integer:
				strncat(token_format, " = %d", MAX_TOKEN - strlen(token_format));
				if (!sscanf(token, token_format, &int_value))
					continue;
				parameter = &int_value;
				break;
			case at_string:
				strncat(token_format, " = %s", MAX_TOKEN - strlen(token_format));
				if (!sscanf(token, token_format, str_value))
					continue;
				parameter = str_value;
				break;
			default:
				/* We should never end in this case */
				fprintf(stderr, "Unknown element type found!\n");
				exit(EXIT_FAILURE);
			}
			if (cmd->func)
				cmd->func(parameter, cfg);
			has_unidentified = false;
			break;
		} while (++cmd);
		if (has_unidentified)
			return token;
	}
	return NULL;
}

void run_file(FILE *trace_file, struct config *cfg)
{
	char *line = malloc(MAX_LINE * sizeof(char));
	char *token = NULL;
	cfg->line_nr = 1;
	while (getline(&line, &(size_t){MAX_LINE}, trace_file) != -1) {
		strncpy(cfg->line, line, MAX_LINE - 1);
		token = parse_elements(line, cmd_main, cfg);
		if (token) {
			fprintf(stderr, "In line %d: '%s'\n", cfg->line_nr, cfg->line);
			fprintf(stderr, "Unknown command: '%s'\n", token);
			exit(EXIT_FAILURE);
		}
		cfg->line_nr++;
	}
	free(line);
}

int main(int argc, char **argv)
{
	struct config cfg = {0};
	cfg.global.pkt = &global_udp_pkt_v6;

	struct xdp_scheduler *skel;

	int opt;
	FILE *trace_file = stdin;
	unsigned long p;
	struct ether_addr *a;

	while ((opt = getopt_long(argc, argv, "f:i:m:a:p:vh",
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'f':
			trace_file = fopen(optarg, "r");
			if (trace_file == NULL) {
				fprintf(stderr, "Error opening file %s: %s\n", optarg,
					strerror(errno));
				return -1;
			}
			break;
		case 'i':
			cfg.global.ifindex = if_nametoindex(optarg);
			if (!cfg.global.ifindex)
				cfg.global.ifindex = strtoul(optarg, NULL, 0);
			if (!cfg.global.ifindex) {
				fprintf(stderr, "Bad interface index or name\n");
				//sample_usage(argv, long_options, __doc__, mask, true);
				return -1;
			}
			if (!if_indextoname(cfg.global.ifindex, cfg.global.ifname)) {
				fprintf(stderr, "Failed to if_indextoname for %d: %s\n",
					cfg.global.ifindex, strerror(errno));
				return -1;
			}
			setmac(&cfg);
			break;
		case 'm':
			a = ether_aton(optarg);
			if (!a) {
				fprintf(stderr, "Invalid MAC: %s\n", optarg);
				return -1;
			}
			memcpy(&cfg.global.pkt->eth.h_source, a, sizeof(*a));
			break;
		case 'a':
			if (!inet_pton(AF_INET6, optarg, &cfg.global.pkt->iph.saddr)) {
				fprintf(stderr, "Invalid IPv6 address: %s\n", optarg);
				return -1;
			}
			break;
		case 'p':
			p = strtoul(optarg, NULL, 0);
			if (!p || p > 0xFFFF) {
				fprintf(stderr, "Invalid port: %s\n", optarg);
				return -1;
			}
			cfg.global.pkt->udp.source = bpf_htons(p);
			break;
		case 'v':
			cfg.verbose = 1;
			break;
		case 'h':
		default:
			//sample_usage(argv, long_options, __doc__, mask, error);
			exit(EXIT_FAILURE);
		}
	}

	//if (argc <= optind) {
	//	//sample_usage(argv, long_options, __doc__, mask, true);
	//	return ret;
	//}

	skel = xdp_scheduler__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF program skel\n");
		exit(EXIT_FAILURE);
	}

	if (xdp_scheduler__load(skel) < 0) {
		fprintf(stderr, "Failed to xdp_scheduler__load: %s\n", strerror(errno));
		exit(EXIT_FAIL_BPF);
	}

	cfg.xdp_prog_fd = bpf_program__fd(skel->progs.xdp_pifo);
	cfg.dequeue_prog_fd = bpf_program__fd(skel->progs.dequeue_pifo);

	run_file(trace_file, &cfg);

	return EXIT_SUCCESS;
}

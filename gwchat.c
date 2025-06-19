// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 *
 * gwchat - Super simple chat app.
 *
 * Server and client are implemented in a single binary.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef __packed
#define __packed __attribute__((__packed__))
#endif

#ifndef noinline
#define noinline __attribute__((__noinline__))
#endif

#ifndef __unused
#define __unused __attribute__((__unused__))
#endif

#ifdef __CHECKER__
#define __must_hold(x) __attribute__((context(x,1,1)))
#define __acquires(x)  __attribute__((context(x,0,1)))
#define __releases(x)  __attribute__((context(x,1,0)))
#else
#define __must_hold(x)
#define __acquires(x)
#define __releases(x)
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>

#include <pthread.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <linux/types.h>
#include <endian.h>

#include "hash_table.h"

enum {
	GWC_PKT_CONN_HANDSHAKE		= 0x01,
	GWC_PKT_CONN_HANDSHAKE_ACK	= 0x02,
	GWC_PKT_CONN_CLOSE		= 0x03,

	GWC_PKT_ACC_REGISTER		= 0x12,
	GWC_PKT_ACC_LOGIN		= 0x13,
	GWC_PKT_ACC_CHANGE_PWD		= 0x14,

	GWC_PKT_CHAN_SUBSCRIBE		= 0x20,
	GWC_PKT_CHAN_UNSUBSCRIBE	= 0x21,
	GWC_PKT_CHAN_LIST		= 0x22,
	GWC_PKT_CHAN_LIST_MSG		= 0x23,
	GWC_PKT_CHAN_SEND_MSG		= 0x24,

	GWC_PKT_RESERVED		= 0xff,
};

struct gwc_pkt_hs {
	__u8	magic;
	__u8	a, b, c;
} __packed;

struct gwc_pkt_acc_udata {
	__u8	ulen;
	__u8	plen;
	__u8	__pad[6];
	char	data[];
} __packed;

struct gwc_pkt_chan_data {
	uint64_t	chan_id;
	uint8_t		nlen;
	char		data[];
} __packed;

struct gwc_pkt {
	__u8	type;
	__u8	flags;
	__be16	len;
	union {
		union {
			struct gwc_pkt_hs		hs;
			struct gwc_pkt_hs		hs_ack;
		} conn;

		union {
			struct gwc_pkt_acc_udata	reg;
			struct gwc_pkt_acc_udata	login;
			struct gwc_pkt_acc_udata	change_pwd;
		} acc;

		union {
			uint64_t	subscribe;
			uint64_t	unsubscribe;
			
		} chan;

		char	__raw[1024];
	};
} __packed;

struct gwc_user {
	uint64_t	id;
	uint8_t		ulen;
	uint8_t		plen;
	char		data[];
} __packed;

struct gwc_srv_cli {
	int			fd;
	struct gwc_user		*user;
	struct gwc_pkt		pkt;
	size_t			pkt_len;
};

struct gwc_srv_wrk {
	int			tcp_fd;
	pthread_t		thread;
	uint32_t		nr_clients;
	struct gwc_srv_cli	*clients;
};

struct gwc_ht {
	hash_table_t		*ht;
	pthread_mutex_t		lock;
};

struct gwc_srv_ctx {
	uint16_t		nr_workers;
	struct gwc_srv_wrk	*workers;
	struct gwc_ht		users;
};

static const struct option server_long_opts[] = {
	{ "help",		no_argument,		NULL,	'h' },
	{ "version",		no_argument,		NULL,	'V' },
	{ "bind-addr",		required_argument,	NULL,	'b' },
	{ "data-dir",		required_argument,	NULL,	'd' },
	{ "nr-workers",		required_argument,	NULL,	'w' },
	{ NULL,			0,			NULL,	0 }
};

static const struct option client_long_opts[] = {
	{ "help",		no_argument,		NULL,	'h' },
	{ "version",		no_argument,		NULL,	'V' },
	{ "server-addr",	required_argument,	NULL,	's' },
	{ "username",		required_argument,	NULL,	'u' },
	{ "password",		required_argument,	NULL,	'p' },
	{ NULL,			0,			NULL,	0 }
};

static int server_run(int argc, char *argv[])
{
	return 0;
}

static int client_run(int argc, char *argv[])
{
	return 0;
}

int main(int argc, char *argv[])
{
	return 0;
}

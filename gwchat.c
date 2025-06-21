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

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>
#include <assert.h>

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
#include <netinet/tcp.h>
#include <sys/mman.h>
#include <signal.h>

#include "hash_table.h"

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
#define __must_hold(x)	__attribute__((context(x,1,1)))
#define __acquires(x)	__attribute__((context(x,0,1)))
#define __releases(x)	__attribute__((context(x,1,0)))
#else
#define __must_hold(x)
#define __acquires(x)
#define __releases(x)
#endif

#ifndef offsetof
#define offsetof(X, Y) ((size_t) &(((X *)0)->Y))
#endif

enum {
	GWC_PKT_CONN_HANDSHAKE		= 0x01,
	GWC_PKT_CONN_HANDSHAKE_ACK	= 0x02,
	GWC_PKT_CONN_CLOSE		= 0x03,

	GWC_PKT_ACC_REGISTER		= 0x12,
	GWC_PKT_ACC_LOGIN		= 0x13,
	GWC_PKT_ACC_CHANGE_PWD		= 0x14,
	/* Response to register/login success. */
	GWC_PKT_ACC_RL_OK		= 0x15,
	/* Response to register/login error.   */
	GWC_PKT_ACC_RL_ERR		= 0x16, 

	GWC_PKT_CHAN_SUBSCRIBE		= 0x20,
	GWC_PKT_CHAN_UNSUBSCRIBE	= 0x21,
	GWC_PKT_CHAN_LIST		= 0x22,
	GWC_PKT_CHAN_LIST_MSG		= 0x23,
	GWC_PKT_CHAN_SEND_MSG		= 0x24,

	GWC_PKT_RESERVED		= 0xff,
};

enum {
	GWC_RL_LOGIN_OK			= 0x01,
	GWC_RL_LOGIN_ERR		= 0x02,
	GWC_RL_REGISTER_OK		= 0x03,
	GWC_RL_REGISTER_ERR		= 0x04,
	GWC_RL_REGISTER_UNAME_EXISTS	= 0x05,
	GWC_RL_REGISTER_UNAME_INVALID	= 0x06,
};

#define ST_ASSERT(X) static_assert(X, #X)

struct gwc_pkt_hs {
	__u8	magic[8];
} __packed;
ST_ASSERT(sizeof(struct gwc_pkt_hs) == 8);

struct gwc_pkt_acc_udata {
	__u8	ulen;
	__u8	plen;
	__u8	__pad[6];
	char	data[];
} __packed;
ST_ASSERT(sizeof(struct gwc_pkt_acc_udata) == 8);
ST_ASSERT(offsetof(struct gwc_pkt_acc_udata, ulen) == 0);
ST_ASSERT(offsetof(struct gwc_pkt_acc_udata, plen) == 1);
ST_ASSERT(offsetof(struct gwc_pkt_acc_udata, __pad) == 2);
ST_ASSERT(offsetof(struct gwc_pkt_acc_udata, data) == 8);

struct gwc_pkt_chan_data {
	__be64	chan_id;
	__u8	nlen;
	__u8	__pad[7];
	char	data[];
} __packed;
ST_ASSERT(sizeof(struct gwc_pkt_chan_data) == 16);
ST_ASSERT(offsetof(struct gwc_pkt_chan_data, chan_id) == 0);
ST_ASSERT(offsetof(struct gwc_pkt_chan_data, nlen) == 8);
ST_ASSERT(offsetof(struct gwc_pkt_chan_data, __pad) == 9);
ST_ASSERT(offsetof(struct gwc_pkt_chan_data, data) == 16);

struct gwc_pkt_chan_list {
	__be64 nr_chan;
	struct gwc_pkt_chan_data channels[];
};
ST_ASSERT(sizeof(struct gwc_pkt_chan_list) == 8);
ST_ASSERT(offsetof(struct gwc_pkt_chan_list, nr_chan) == 0);
ST_ASSERT(offsetof(struct gwc_pkt_chan_list, channels) == 8);

struct gwc_hdr_pkt {
	__u8	type;
	__u8	flags;
	__be16	len;
} __packed;
ST_ASSERT(sizeof(struct gwc_hdr_pkt) == 4);
ST_ASSERT(offsetof(struct gwc_hdr_pkt, type) == 0);
ST_ASSERT(offsetof(struct gwc_hdr_pkt, flags) == 1);
ST_ASSERT(offsetof(struct gwc_hdr_pkt, len) == 2);

struct gwc_pkt {
	struct gwc_hdr_pkt	hdr;
	union {
		union {
			struct gwc_pkt_hs		hs;
			struct gwc_pkt_hs		hs_ack;
		} conn __packed;

		union {
			struct gwc_pkt_acc_udata	reg;
			struct gwc_pkt_acc_udata	login;
			struct gwc_pkt_acc_udata	change_pwd;
			uint8_t				rl_resp;
		} acc __packed;

		union {
			__be64				subscribe;
			__be64				unsubscribe;
			struct gwc_pkt_chan_list	chan_list;
		} chan __packed;

		char	__raw[4096 - sizeof(struct gwc_hdr_pkt)];
	} __packed;
} __packed;
ST_ASSERT(sizeof(struct gwc_pkt) == 4096);
ST_ASSERT(offsetof(struct gwc_pkt, hdr) == 0);
ST_ASSERT(sizeof(struct gwc_hdr_pkt) == offsetof(struct gwc_pkt, conn));
ST_ASSERT(sizeof(struct gwc_hdr_pkt) == offsetof(struct gwc_pkt, conn.hs));
ST_ASSERT(sizeof(struct gwc_hdr_pkt) == offsetof(struct gwc_pkt, conn.hs_ack));
ST_ASSERT(sizeof(struct gwc_hdr_pkt) == offsetof(struct gwc_pkt, acc));
ST_ASSERT(sizeof(struct gwc_hdr_pkt) == offsetof(struct gwc_pkt, acc.reg));
ST_ASSERT(sizeof(struct gwc_hdr_pkt) == offsetof(struct gwc_pkt, acc.login));
ST_ASSERT(sizeof(struct gwc_hdr_pkt) == offsetof(struct gwc_pkt, acc.change_pwd));
ST_ASSERT(sizeof(struct gwc_hdr_pkt) == offsetof(struct gwc_pkt, chan));
ST_ASSERT(sizeof(struct gwc_hdr_pkt) == offsetof(struct gwc_pkt, chan.subscribe));
ST_ASSERT(sizeof(struct gwc_hdr_pkt) == offsetof(struct gwc_pkt, chan.unsubscribe));
ST_ASSERT(sizeof(struct gwc_hdr_pkt) == offsetof(struct gwc_pkt, chan.chan_list));


#define GWC_USER_MIN_SIZE	(8 + 1 + 1 + 512)

struct gwc_user {
	uint64_t	id;
	char		uname[128];
	char		pwd[128];
} __packed;

struct gwc_channel {
	uint64_t	id;
	char		name[128];
	char		desc[512];
	uint64_t	nr_subscribers;
	uint64_t	nr_messages;
	uint64_t	last_msg_id;
} __packed;

struct gwc_message {
	uint64_t	id;
	uint64_t	chan_id;
	uint64_t	user_id;
	uint64_t	timestamp;
	char		data[512];
} __packed;

struct gwc_buf {
	char		*buf;
	uint32_t	len;
	uint32_t	cap;
	char		*orig;
};

static int gwc_buf_init(struct gwc_buf *b, uint32_t cap)
{
	b->buf = malloc(cap + 1);
	if (!b->buf)
		return -ENOMEM;

	b->orig = b->buf;
	b->cap = cap;
	b->len = 0;
	b->buf[cap] = '\0';
	return 0;
}

static void gwc_buf_free(struct gwc_buf *b)
{
	if (b->buf) {
		free(b->orig);
		memset(b, 0, sizeof(*b));
	}
}

static void gwc_buf_soft_advance(struct gwc_buf *b, uint32_t len)
{
	b->len -= len;
	b->buf += len;
	assert(b->len <= b->cap);
}

static void gwc_buf_sync(struct gwc_buf *b)
{
	if (b->buf == b->orig)
		return;

	if (!b->len) {
		gwc_buf_free(b);
		return;
	}

	assert(b->len < b->cap);
	assert(b->orig < b->buf);
	memmove(b->orig, b->buf, b->len);
	b->buf = b->orig;
}

static int gwc_buf_append(struct gwc_buf *b, const void *data, uint32_t len)
{
	gwc_buf_sync(b);
	if (b->len + len > b->cap) {
		uint32_t new_cap = b->cap ? b->cap * 2 : 64;
		char *new_buf;

		while (new_cap < b->len + len)
			new_cap *= 2;

		new_buf = realloc(b->buf, new_cap + 1);
		if (!new_buf)
			return -ENOMEM;

		b->buf = new_buf;
		b->cap = new_cap;
	}

	memcpy(b->buf + b->len, data, len);
	b->len += len;
	b->buf[b->len] = '\0';
	return 0;
}

struct gwc_srv_cli {
	int			fd;
	struct gwc_user		*user;
	struct sockaddr_storage	addr;
	size_t			rc_len;
	struct gwc_pkt		rc_buf;
	struct gwc_buf		sn_buf;
};

struct gwc_srv_ctx;

struct gwc_srv_cli_arr {
	struct pollfd		*pfd;
	struct gwc_srv_cli	*clients;
	uint32_t		nr;
	uint32_t		cap;
};

struct gwc_srv_wrk {
	int			tcp_fd;
	bool			accept_stopped;
	uint16_t		tid;
	pthread_t		thread;
	struct gwc_srv_cli_arr	cli_arr;
	struct gwc_srv_ctx	*ctx;
};

struct gwc_ht {
	hash_table_t		*ht;
	pthread_mutex_t		lock;
};

struct gwc_srv_cfg {
	char		bind_addr[255];
	char		data_dir[512];
	uint16_t	nr_workers;
};

struct gwc_table {
	int		fd;
	void		*mem;
	size_t		size;
};

struct gwc_srv_db {
	struct gwc_table	users;
	struct gwc_table	channels;
	struct gwc_table	messages;
	struct gwc_table	chan_subs;
};

struct gwc_srv_ctx {
	volatile bool		stop;
	struct gwc_srv_wrk	*workers;
	struct gwc_ht		users;
	struct gwc_srv_db	db;
	struct gwc_srv_cfg	cfg;
	struct sockaddr_storage	bind_addr;
	socklen_t		bind_addr_len;
};

struct gwc_cli_cfg {
	char		server_addr[255];
	char		uname[128];
	char		pwd[128];
	bool		do_register;
};

struct gwc_cli_ctx {
	volatile bool		stop;
	int			tcp_fd;
	struct pollfd		pfd[2];
	size_t			rc_len;
	struct gwc_pkt		rc_buf;
	struct gwc_buf		sn_buf;
	struct gwc_cli_cfg	cfg;
	struct sockaddr_storage	server_addr;
	socklen_t		server_addr_len;
};

static inline const char *gwc_user_uname(struct gwc_user *u)
{
	return u->uname;
}

static inline const char *gwc_user_pwd(struct gwc_user *u)
{
	return u->pwd;
}

static inline size_t pkt_hdr_prep(struct gwc_pkt *p, uint8_t type, size_t len)
{
	p->hdr.type = type;
	p->hdr.flags = 0;
	p->hdr.len = htobe16(len);
	return sizeof(p->hdr) + len;
}

static inline size_t pkt_prep_conn_hs(struct gwc_pkt *p)
{
	memcpy(&p->conn.hs.magic, "gwchat01", 8);
	return pkt_hdr_prep(p, GWC_PKT_CONN_HANDSHAKE, sizeof(p->conn.hs));
}

static inline size_t pkt_prep_conn_hs_ack(struct gwc_pkt *p)
{
	return pkt_prep_conn_hs(p);
}

static inline size_t pkt_prep_conn_close(struct gwc_pkt *p)
{
	return pkt_hdr_prep(p, GWC_PKT_CONN_CLOSE, 0);
}

static inline size_t pkt_prep_acc_reg(struct gwc_pkt *p, const char *uname,
				      const char *pwd)
{
	size_t ulen = strlen(uname);
	size_t plen = strlen(pwd);
	size_t len = sizeof(p->acc.reg) + ulen + 1 + plen + 1;

	if (ulen > 255 || plen > 255)
		return 0;

	p->acc.reg.ulen = ulen;
	p->acc.reg.plen = plen;
	memcpy(p->acc.reg.data, uname, ulen);
	p->acc.reg.data[ulen] = '\0';
	memcpy(&p->acc.reg.data[ulen + 1], pwd, plen);
	p->acc.reg.data[ulen + 1 + plen] = '\0';

	return pkt_hdr_prep(p, GWC_PKT_ACC_REGISTER, len);
}

static inline size_t pkt_prep_acc_login(struct gwc_pkt *p, const char *uname,
					const char *pwd)
{
	size_t ulen = strlen(uname);
	size_t plen = strlen(pwd);
	size_t len = sizeof(p->acc.login) + ulen + 1 + plen + 1;

	if (ulen > 255 || plen > 255)
		return 0;

	p->acc.login.ulen = ulen;
	p->acc.login.plen = plen;
	memcpy(p->acc.login.data, uname, ulen);
	p->acc.login.data[ulen] = '\0';
	memcpy(&p->acc.login.data[ulen + 1], pwd, plen);
	p->acc.login.data[ulen + 1 + plen] = '\0';

	return pkt_hdr_prep(p, GWC_PKT_ACC_LOGIN, len);
}

static inline size_t pkt_prep_acc_change_pwd(struct gwc_pkt *p,
					     const char *uname,
					     const char *pwd)
{
	size_t ulen = strlen(uname);
	size_t plen = strlen(pwd);
	size_t len = sizeof(p->acc.change_pwd) + ulen + 1 + plen + 1;

	if (ulen > 255 || plen > 255)
		return 0;

	p->acc.change_pwd.ulen = ulen;
	p->acc.change_pwd.plen = plen;
	memcpy(p->acc.change_pwd.data, uname, ulen);
	p->acc.change_pwd.data[ulen] = '\0';
	memcpy(&p->acc.change_pwd.data[ulen + 1], pwd, plen);
	p->acc.change_pwd.data[ulen + 1 + plen] = '\0';

	return pkt_hdr_prep(p, GWC_PKT_ACC_CHANGE_PWD, len);
}

static inline size_t pkt_prep_chan_subscribe(struct gwc_pkt *p,
					     uint64_t chan_id)
{
	p->chan.subscribe = htobe64(chan_id);
	return pkt_hdr_prep(p, GWC_PKT_CHAN_SUBSCRIBE,
			    sizeof(p->chan.subscribe));
}

static inline size_t pkt_prep_chan_unsubscribe(struct gwc_pkt *p,
					       uint64_t chan_id)
{
	p->chan.unsubscribe = htobe64(chan_id);
	return pkt_hdr_prep(p, GWC_PKT_CHAN_UNSUBSCRIBE,
			    sizeof(p->chan.unsubscribe));
}

static inline size_t pkt_prep_chan_list(struct gwc_pkt *p, uint64_t nr_chan)
{
	p->chan.chan_list.nr_chan = htobe64(nr_chan);
	return pkt_hdr_prep(p, GWC_PKT_CHAN_LIST, sizeof(p->chan.chan_list));
}

static const struct option server_long_opts[] = {
	{ "help",		no_argument,		NULL,	'h' },
	{ "bind-addr",		required_argument,	NULL,	'b' },
	{ "data-dir",		required_argument,	NULL,	'd' },
	{ "nr-workers",		required_argument,	NULL,	'w' },
	{ NULL,			0,			NULL,	0 }
};
static const char server_opts[] = "hb:d:w:";

static const struct option client_long_opts[] = {
	{ "help",		no_argument,		NULL,	'h' },
	{ "server-addr",	required_argument,	NULL,	's' },
	{ "username",		required_argument,	NULL,	'u' },
	{ "password",		required_argument,	NULL,	'p' },
	{ "register",		no_argument,		NULL,	'R' },
	{ NULL,			0,			NULL,	0 }
};
static const char client_opts[] = "hs:u:p:R";

static const struct gwc_srv_cfg default_srv_cfg = {
	.bind_addr = "[::]:8181",
	.data_dir = "/tmp/gwchat_server",
	.nr_workers = 4,
};

static void show_server_usage(const char *app)
{
	fprintf(stderr, "Usage: %s [options]\n", app);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -h, --help            Show this help message\n");
	fprintf(stderr, "  -b, --bind-addr       Set the bind address (default: %s)\n", default_srv_cfg.bind_addr);
	fprintf(stderr, "  -d, --data-dir        Set the data directory (default: %s)\n", default_srv_cfg.data_dir);
	fprintf(stderr, "  -w, --nr-workers      Set the number of worker threads (default: %hu)\n", default_srv_cfg.nr_workers);
	exit(0);
}

static void show_client_usage(const char *app)
{
	fprintf(stderr, "Usage: %s [options]\n", app);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -h, --help            Show this help message\n");
	fprintf(stderr, "  -s, --server-addr     Set the server address (default: %s)\n", "[::1]:8181");
	fprintf(stderr, "  -u, --username        Set the username for register/login\n");
	fprintf(stderr, "  -p, --password        Set the password for register/login\n");
	fprintf(stderr, "  -R, --register        Register a new user with the given username and password\n");
	exit(0);
}

#define INET_FULL_ADDRSTRLEN (INET6_ADDRSTRLEN + sizeof("[]:65535") + 1)

static const char *skaddr_to_str_r(char buf[INET_FULL_ADDRSTRLEN],
				   const struct sockaddr_storage *ss)
{
	const struct sockaddr_in6 *i6 = (void *)ss;
	const struct sockaddr_in *i4 = (void *)ss;
	int f = ss->ss_family;

	if (f == AF_INET) {
		if (!inet_ntop(f, &i4->sin_addr, buf, INET_FULL_ADDRSTRLEN))
			return NULL;
		sprintf(buf + strlen(buf), ":%hu", ntohs(i4->sin_port));
	} else if (f == AF_INET6) {
		if (!inet_ntop(f, &i6->sin6_addr, buf + 1, INET_FULL_ADDRSTRLEN))
			return NULL;
		buf[0] = '[';
		sprintf(buf + strlen(buf), "]:%hu", ntohs(i6->sin6_port));
	} else {
		strncpy(buf, "UNKNOWN_FAMILY", INET_FULL_ADDRSTRLEN - 1);
		buf[INET_FULL_ADDRSTRLEN - 1] = '\0';
		return NULL;
	}

	return buf;
}

static const char *skaddr_to_str(const struct sockaddr_storage *ss)
{
	__thread static char __buf[8][INET_FULL_ADDRSTRLEN];
	__thread static uint8_t idx;
	char *b = __buf[idx++ % 8];

	return skaddr_to_str_r(b, ss);
}

static int server_parse_argv(int argc, char *argv[], struct gwc_srv_ctx *ctx)
{
	size_t l;
	int c;

	ctx->cfg = default_srv_cfg;
	while (1) {
		c = getopt_long(argc - 1, argv + 1, server_opts,
				server_long_opts, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			show_server_usage(argv[0]);
			break;
		case 'b':
			l = sizeof(ctx->cfg.bind_addr) - 1;
			strncpy(ctx->cfg.bind_addr, optarg, l);
			ctx->cfg.bind_addr[l] = '\0';
			break;
		case 'd':
			l = sizeof(ctx->cfg.data_dir) - 1;
			strncpy(ctx->cfg.data_dir, optarg, l);
			ctx->cfg.data_dir[l] = '\0';
			break;
		case 'w':
			c = atoi(optarg);
			if (c < 1 || c > 1024) {
				fprintf(stderr, "Invalid number of workers: %d\n", c);
				return -EINVAL;
			}
			ctx->cfg.nr_workers = c;
			break;
		default:
		case '?':
			fprintf(stderr, "Unknown option: %c\n", c);
			show_server_usage(argv[0]);
			break;
		}
	}

	return 0;
}

static int client_parse_argv(int argc, char *argv[], struct gwc_cli_ctx *ctx)
{
	struct {
		bool has_s;
		bool has_u;
		bool has_p;
	} x;
	size_t l;
	int c;

	memset(&x, 0, sizeof(x));
	memset(ctx, 0, sizeof(*ctx));
	while (1) {
		c = getopt_long(argc - 1, argv + 1, client_opts,
				client_long_opts, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			show_client_usage(argv[0]);
			break;
		case 's':
			l = sizeof(ctx->cfg.server_addr) - 1;
			strncpy(ctx->cfg.server_addr, optarg, l);
			ctx->cfg.server_addr[l] = '\0';
			x.has_s = true;
			break;
		case 'u':
			l = sizeof(ctx->cfg.uname) - 1;
			strncpy(ctx->cfg.uname, optarg, l);
			ctx->cfg.uname[l] = '\0';
			x.has_u = true;
			break;
		case 'p':
			l = sizeof(ctx->cfg.pwd) - 1;
			strncpy(ctx->cfg.pwd, optarg, l);
			ctx->cfg.pwd[l] = '\0';
			x.has_p = true;
			break;
		case 'R':
			ctx->cfg.do_register = true;
			break;
		default:
		case '?':
			fprintf(stderr, "Unknown option: %c\n", c);
			show_client_usage(argv[0]);
			break;
		}
	}

	if (!x.has_s) {
		fprintf(stderr, "Server address is required (-s, --server-addr).\n");
		show_client_usage(argv[0]);
		return -EINVAL;
	}

	return 0;
}

static int gwc_srv_realloc_cli_arr(struct gwc_srv_cli_arr *arr, uint32_t new_cap)
{
	struct gwc_srv_cli *new_clients;
	struct pollfd *new_pfd;

	assert(new_cap >= arr->nr);
	new_clients = realloc(arr->clients, new_cap * sizeof(*new_clients));
	if (!new_clients)
		return -ENOMEM;
	arr->clients = new_clients;

	new_pfd = realloc(arr->pfd, (new_cap + 1) * sizeof(*new_pfd));
	if (!new_pfd)
		return -ENOMEM;
	arr->pfd = new_pfd;
	arr->cap = new_cap;
	return 0;
}

static int gwc_srv_resize_arr_if_needed(struct gwc_srv_cli_arr *arr)
{
	if (arr->nr < arr->cap)
		return 0;

	return gwc_srv_realloc_cli_arr(arr, (arr->cap + 1) * 2);
}

static int gwc_srv_shrink_arr_if_reasonable(struct gwc_srv_cli_arr *arr)
{
	uint32_t new_cap, empty_slots;

	if (arr->cap <= 16)
		return 0;

	empty_slots = arr->cap - arr->nr;
	if (empty_slots > (arr->cap / 2))
		return 0;

	new_cap = arr->cap / 2;
	if (new_cap < 16)
		new_cap = 16;

	return gwc_srv_realloc_cli_arr(arr, new_cap);
}

static int gwc_srv_push_client(struct gwc_srv_wrk *w, int fd,
			       struct sockaddr_storage *addr,
			       socklen_t addr_len)
{
	struct gwc_srv_cli *c;
	struct pollfd *pfd;
	int r = gwc_srv_resize_arr_if_needed(&w->cli_arr);
	if (r < 0)
		return r;

	c = &w->cli_arr.clients[w->cli_arr.nr];
	r = gwc_buf_init(&c->sn_buf, 1024);
	if (r < 0)
		return r;

	c->fd = fd;
	c->user = NULL;
	c->rc_len = 0;
	c->addr = *addr;

	pfd = &w->cli_arr.pfd[w->cli_arr.nr + 1];
	pfd->fd = fd;
	pfd->events = POLLIN | POLLRDHUP;
	pfd->revents = 0;
	w->cli_arr.nr++;
	return 0;
}

static int gwc_srv_handle_accept_error(struct gwc_srv_wrk *w, int err)
{
	if (err == -EAGAIN || err == -EINTR)
		return 0;

	if (err == -ENFILE || err == -EMFILE) {
		fprintf(stderr, "Too many open files, cannot accept new connections.\n");
		w->cli_arr.pfd[0].fd = -1;
		w->accept_stopped = true;
		return 0;
	}

	return err;
}

static int gwc_srv_handle_event_accept(struct gwc_srv_wrk *w)
{
	static const int flags = SOCK_CLOEXEC | SOCK_NONBLOCK;
	socklen_t addr_len = w->ctx->bind_addr_len;
	struct sockaddr_storage addr;
	int fd, r;

	fd = accept4(w->tcp_fd, (struct sockaddr *)&addr, &addr_len, flags);
	if (fd < 0)
		return gwc_srv_handle_accept_error(w, -errno);

	r = gwc_srv_push_client(w, fd, &addr, addr_len);
	if (r < 0) {
		fprintf(stderr, "Failed to push client: %s\n", strerror(-r));
		close(fd);
		return r;
	}

	printf("Accepted connection from %s\n", skaddr_to_str(&addr));
	return 0;
}

static int gwc_srv_register_user(struct gwc_srv_wrk *w, struct gwc_srv_cli *c,
				 const char *uname, const char *pwd)
{
	return 0;
}

static int gwc_srv_handle_event_send(struct gwc_srv_wrk *w,
				     struct gwc_srv_cli *c);

static int gwc_srv_handle_pkt_conn_hs(struct gwc_srv_wrk *w,
				      struct gwc_srv_cli *c)
{
	struct gwc_pkt *p = &c->rc_buf;
	struct gwc_pkt resp;
	size_t len;

	if (p->hdr.len != sizeof(p->conn.hs))
		return -EINVAL;
	if (memcmp(p->conn.hs.magic, "gwchat01", 8))
		return -EINVAL;

	len = pkt_prep_conn_hs_ack(&resp);
	if (gwc_buf_append(&c->sn_buf, &resp, len) < 0)
		return -ENOMEM;

	return 0;
}

static int gwc_srv_handle_pkt_acc_reg(struct gwc_srv_wrk *w,
				      struct gwc_srv_cli *c)
{
	struct gwc_pkt_acc_udata *reg = &c->rc_buf.acc.reg;
	struct gwc_pkt *p = &c->rc_buf;
	char uname[128], pwd[128];
	size_t tot_len;

	if (p->hdr.len < sizeof(p->acc.reg))
		return -EINVAL;
	if (reg->ulen > 127 || reg->plen > 127)
		return -EINVAL;
	tot_len = sizeof(*reg) + reg->ulen + reg->plen + 2;
	if (p->hdr.len != tot_len)
		return -EINVAL;

	strncpy(uname, reg->data, sizeof(uname) - 1);
	uname[sizeof(uname) - 1] = '\0';
	strncpy(pwd, &reg->data[reg->ulen + 1], sizeof(pwd) - 1);
	pwd[sizeof(pwd) - 1] = '\0';
	return gwc_srv_register_user(w, c, uname, pwd);
}

static int gwc_srv_handle_cli_pkt(struct gwc_srv_wrk *w, struct gwc_srv_cli *c)
{
	switch (c->rc_buf.hdr.type) {
	case GWC_PKT_CONN_HANDSHAKE:
		return gwc_srv_handle_pkt_conn_hs(w, c);
	case GWC_PKT_CONN_HANDSHAKE_ACK:
		return -EINVAL;
	case GWC_PKT_CONN_CLOSE:
		return -ECONNRESET;
	case GWC_PKT_ACC_REGISTER:
		return gwc_srv_handle_pkt_acc_reg(w, c);
	// case GWC_PKT_ACC_LOGIN:
	// 	return gwc_srv_handle_pkt_acc_login(w, c);
	// case GWC_PKT_ACC_CHANGE_PWD:
	// 	return gwc_srv_handle_pkt_acc_change_pwd(w, c);
	// case GWC_PKT_CHAN_SUBSCRIBE:
	// 	return gwc_srv_handle_pkt_chan_subscribe(w, c);
	// case GWC_PKT_CHAN_UNSUBSCRIBE:
	// 	return gwc_srv_handle_pkt_chan_unsubscribe(w, c);
	// case GWC_PKT_CHAN_LIST:
	// 	return gwc_srv_handle_pkt_chan_list(w, c);
	// case GWC_PKT_CHAN_LIST_MSG:
	// 	return gwc_srv_handle_pkt_chan_list_msg(w, c);
	// case GWC_PKT_CHAN_SEND_MSG:
	// 	return gwc_srv_handle_pkt_chan_send_msg(w, c);
	case GWC_PKT_RESERVED:
	default:
		return -EINVAL;
	}
}

static int __gwc_srv_handle_event_recv(struct gwc_srv_wrk *w,
				       struct gwc_srv_cli *c)
{
	size_t len, expected_len, received_len;
	struct gwc_pkt *p;
	int r;

repeat:
	p = &c->rc_buf;
	received_len = c->rc_len;
	if (received_len < sizeof(p->hdr))
		return -EAGAIN;

	len = be16toh(p->hdr.len);
	expected_len = sizeof(p->hdr) + len;
	if (received_len < expected_len)
		return -EAGAIN;

	p->hdr.len = len;
	r = gwc_srv_handle_cli_pkt(w, c);
	if (r)
		return r;

	c->rc_len -= expected_len;
	if (c->rc_len) {
		char *dst = (char *)&c->rc_buf;
		char *src = dst + expected_len;
		memmove(dst, src, c->rc_len);
	}

	if (c->sn_buf.len) {
		r = gwc_srv_handle_event_send(w, c);
		if (r)
			return r;
	}

	if (c->rc_len)
		goto repeat;

	return 0;
}

static int gwc_srv_handle_event_recv(struct gwc_srv_wrk *w,
				     struct gwc_srv_cli *c)
{
	ssize_t ret;
	size_t len;
	char *buf;

	buf = (char *)&c->rc_buf + c->rc_len;
	len = sizeof(c->rc_buf) - c->rc_len;
	ret = recv(c->fd, buf, len, MSG_NOSIGNAL | MSG_DONTWAIT);
	if (ret < 0) {
		ret = -errno;
		if (ret == -EAGAIN || ret == -EINTR)
			return 0;

		return ret;
	} else if (!ret) {
		return -ECONNRESET;
	}

	c->rc_len += (size_t)ret;
	assert(c->rc_len <= sizeof(c->rc_buf));
	return __gwc_srv_handle_event_recv(w, c);
}

static int gwc_srv_handle_event_send(struct gwc_srv_wrk *w,
				     struct gwc_srv_cli *c)
{
	size_t len, rr;
	ssize_t ret;
	char *buf;

	len = c->sn_buf.len;
	if (!len)
		return 0;

	buf = c->sn_buf.buf;
	ret = send(c->fd, buf, len, MSG_NOSIGNAL | MSG_DONTWAIT);
	if (ret < 0) {
		ret = -errno;
		if (ret == -EAGAIN || ret == -EINTR)
			return 0;

		return ret;
	} else if (!ret) {
		return -ECONNRESET;
	}

	rr = (size_t)ret;
	assert(rr <= len);
	gwc_buf_soft_advance(&c->sn_buf, rr);

	if (!c->sn_buf.len && c->rc_len)
		return gwc_srv_handle_cli_pkt(w, c);

	return 0;
}

static int gwc_srv_handle_event_close(struct gwc_srv_wrk *w, int i)
{
	struct gwc_srv_cli_arr *arr = &w->cli_arr;
	uint32_t last = w->cli_arr.nr;
	uint32_t idx = i + 1;

	close(arr->clients[i].fd);
	arr->clients[i].fd = -1;
	arr->pfd[idx] = arr->pfd[last];
	arr->clients[i] = arr->clients[last - 1];
	arr->nr--;

	if (w->accept_stopped) {
		arr->pfd[0].fd = w->tcp_fd;
		w->accept_stopped = false;
	}

	return gwc_srv_shrink_arr_if_reasonable(arr);
}

static int gwc_srv_handle_event(struct gwc_srv_wrk *w, int i, short events)
{
	struct gwc_srv_cli *c = &w->cli_arr.clients[i];

	if (events & POLLIN) {
		if (gwc_srv_handle_event_recv(w, c))
			goto out_close;
	}

	if (events & POLLOUT) {
		if (gwc_srv_handle_event_send(w, c))
			goto out_close;
	}

	if (events & (POLLHUP | POLLERR | POLLRDHUP))
		goto out_close;

	return 0;

out_close:
	return gwc_srv_handle_event_close(w, i);
}

static int gwc_srv_handle_events(struct gwc_srv_wrk *w, int nr_events)
{
	struct pollfd *pfd = w->cli_arr.pfd;
	int i, r = 0, n = w->cli_arr.nr;

	if (pfd[0].revents) {
		r = gwc_srv_handle_event_accept(w);
		if (r < 0) {
			fprintf(stderr, "Failed to handle accept event: %s\n", strerror(-r));
			return r;
		}
		nr_events--;
	}

	pfd++;
	for (i = 0; i < n; i++) {
		if (!nr_events)
			break;

		if (!pfd[i].revents)
			continue;

		nr_events--;
		r = gwc_srv_handle_event(w, i, pfd[i].revents);
		if (r < 0)
			break;
	}

	return r;
}

static int gwc_srv_fish_events(struct gwc_srv_wrk *w)
{
	int r;

	r = poll(w->cli_arr.pfd, w->cli_arr.nr + 1, -1);
	if (r < 0) {
		r = -errno;
		return (r == -EINTR) ? 0 : r;
	}

	return r;
}

static void *gwc_srv_worker_func(void *arg)
{
	struct gwc_srv_wrk *w = arg;
	struct gwc_srv_ctx *ctx = w->ctx;
	int r = 0;

	if (!ctx->stop) {
		if (!w->tid) {
			printf("Master worker started.\n");
			printf("Listening on %s...\n", ctx->cfg.bind_addr);
		} else {
			printf("Worker %hu started.\n", w->tid);
		}
	}

	while (!ctx->stop) {
		r = gwc_srv_fish_events(w);
		if (r < 0)
			break;
		r = gwc_srv_handle_events(w, r);
		if (r < 0)
			break;
	}

	return (void *)(intptr_t)r;
}

static int gwc_srv_open_table(const char *dir, const char *fname,
			      struct gwc_table *tb)
{
	char *full_fname;
	struct stat st;
	void *mem;
	int fd, r;

	full_fname = malloc(strlen(dir) + strlen(fname) + 2);
	if (!full_fname)
		return -ENOMEM;

	sprintf(full_fname, "%s/%s", dir, fname);
	fd = open(full_fname, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
	if (fd < 0) {
		r = -errno;
		goto out_err;
	}

	r = fstat(fd, &st);
	if (r < 0) {
		r = -errno;
		goto out_close;
	}

	tb->size = st.st_size;
	if (!tb->size) {
		tb->size = 1024 * 10;
		r = ftruncate(fd, tb->size);
		if (r < 0) {
			r = -errno;
			goto out_close;
		}
	}

	mem = mmap(NULL, tb->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED) {
		r = -errno;
		goto out_close;
	}

	tb->fd = fd;
	tb->mem = mem;
	free(full_fname);
	return 0;

out_close:
	close(fd);
out_err:
	fprintf(stderr, "Failed to open table '%s': %s\n", full_fname, strerror(-r));
	free(full_fname);
	return r;
}

static void gwc_srv_close_table(struct gwc_table *tb)
{
	if (tb->mem) {
		msync(tb->mem, tb->size, MS_ASYNC);
		munmap(tb->mem, tb->size);
		tb->mem = NULL;
	}

	if (tb->fd >= 0) {
		close(tb->fd);
		tb->fd = -1;
	}

	tb->size = 0;
}

static int gwc_srv_free_storage(struct gwc_srv_ctx *ctx)
{
	struct gwc_srv_db *db = &ctx->db;

	gwc_srv_close_table(&db->chan_subs);
	gwc_srv_close_table(&db->messages);
	gwc_srv_close_table(&db->channels);
	gwc_srv_close_table(&db->users);
	return 0;
}

static int gwc_srv_init_storage(struct gwc_srv_ctx *ctx)
{
	const char *dir = ctx->cfg.data_dir;
	struct gwc_srv_db *db = &ctx->db;
	int r = 0;

	r = mkdir(dir, 0755);
	if (r < 0 && errno != EEXIST) {
		r = -errno;
		fprintf(stderr, "Failed to create directory '%s': %s\n", dir,
			strerror(-r));
		return r;
	}

	r = gwc_srv_open_table(dir, "tb_users.bin", &db->users);
	if (r)
		return r;
	r = gwc_srv_open_table(dir, "tb_channels.bin", &db->channels);
	if (r)
		goto oe_users;
	r = gwc_srv_open_table(dir, "tb_messages.bin", &db->messages);
	if (r)
		goto oe_channels;
	r = gwc_srv_open_table(dir, "tb_chan_subs.bin", &db->chan_subs);
	if (r)
		goto oe_messages;

	return 0;

oe_messages:
	gwc_srv_close_table(&db->messages);
oe_channels:
	gwc_srv_close_table(&db->channels);
oe_users:
	gwc_srv_close_table(&db->users);
	return r;
}

static int gwc_srv_init_worker_cli_arr(struct gwc_srv_wrk *w)
{
	static const uint32_t init_cap = 16;
	struct gwc_srv_cli *clients;
	struct pollfd *pfd;
	uint32_t i;

	clients = calloc(init_cap, sizeof(*clients));
	if (!clients)
		return -ENOMEM;

	pfd = calloc(init_cap + 1, sizeof(*pfd));
	if (!pfd) {
		free(clients);
		return -ENOMEM;
	}

	pfd[0].fd = w->tcp_fd;
	pfd[0].events = POLLIN | POLLRDHUP;
	pfd[0].revents = 0;

	for (i = 0; i < init_cap; i++) {
		uint32_t j = i + 1;
		clients[i].fd = -1;
		pfd[j].fd = -1;
		pfd[j].events = POLLIN | POLLRDHUP;
		pfd[j].revents = 0;
	}

	w->cli_arr.clients = clients;
	w->cli_arr.pfd = pfd;
	w->cli_arr.nr = 0;
	w->cli_arr.cap = init_cap;
	return 0;
}

static void gwc_srv_free_worker_cli_arr(struct gwc_srv_wrk *w)
{
	if (w->cli_arr.clients) {
		free(w->cli_arr.clients);
		w->cli_arr.clients = NULL;
	}
	if (w->cli_arr.pfd) {
		free(w->cli_arr.pfd);
		w->cli_arr.pfd = NULL;
	}

	w->cli_arr.nr = 0;
	w->cli_arr.cap = 0;
}

static int gwc_srv_init_worker_sock(struct gwc_srv_wrk *w)
{
	struct sockaddr *addr = (struct sockaddr *)&w->ctx->bind_addr;
	socklen_t addr_len = w->ctx->bind_addr_len;
	int fd, r, v = 1;
	socklen_t l = sizeof(v);

	fd = socket(addr->sa_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &v, l);
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &v, l);

	r = bind(fd, addr, addr_len);
	if (r < 0)
		goto out_err;

	r = listen(fd, SOMAXCONN);
	if (r < 0)
		goto out_err;

	w->tcp_fd = fd;
	return 0;

out_err:
	r = -errno;
	close(fd);
	w->tcp_fd = -1;
	return r;
}

static void gwc_srv_free_worker_sock(struct gwc_srv_wrk *w)
{
	if (w->tcp_fd >= 0) {
		close(w->tcp_fd);
		w->tcp_fd = -1;
	}
}

static int gwc_srv_init_worker(struct gwc_srv_wrk *w)
{
	int r;

	r = gwc_srv_init_worker_sock(w);
	if (r < 0) {
		fprintf(stderr, "Failed to initialize worker socket: %s\n",
			strerror(-r));
		return r;
	}

	r = gwc_srv_init_worker_cli_arr(w);
	if (r < 0) {
		fprintf(stderr, "Failed to initialize worker client array: %s\n",
			strerror(-r));
		goto oe_sock;
	}

	if (!w->tid)
		return 0;

	r = pthread_create(&w->thread, NULL, &gwc_srv_worker_func, w);
	if (r < 0) {
		r = -r;
		fprintf(stderr, "Failed to create worker thread: %s\n",
			strerror(-r));
		goto oe_cli_arr;
	}

	return 0;

oe_cli_arr:
	gwc_srv_free_worker_cli_arr(w);
oe_sock:
	gwc_srv_free_worker_sock(w);
	return r;
}

static int gwc_srv_free_worker(struct gwc_srv_wrk *w)
{
	w->ctx->stop = false;
	shutdown(w->tcp_fd, SHUT_RDWR);
	pthread_kill(w->thread, SIGTERM);
	pthread_join(w->thread, NULL);

	if (w->tcp_fd >= 0) {
		close(w->tcp_fd);
		w->tcp_fd = -1;
	}

	gwc_srv_free_worker_cli_arr(w);
	return 0;
}

static int gwc_srv_init_workers(struct gwc_srv_ctx *ctx)
{
	size_t i, nr_workers = ctx->cfg.nr_workers;
	struct gwc_srv_wrk *workers;
	int r;

	workers = calloc(nr_workers, sizeof(*workers));
	if (!workers)
		return -ENOMEM;

	ctx->stop = false;
	for (i = 0; i < nr_workers; i++) {
		workers[i].tcp_fd = -1;
		workers[i].ctx = ctx;
		workers[i].tid = i;
		r = gwc_srv_init_worker(&workers[i]);
		if (r)
			goto out_err;
	}

	ctx->workers = workers;
	return 0;

out_err:
	while (i--)
		gwc_srv_free_worker(&workers[i]);
	free(workers);
	return r;
}

static int string_to_sockaddr(struct sockaddr_storage *addr,
			      socklen_t *addr_len, const char *str)
{
	struct sockaddr_in6 *i6 = (struct sockaddr_in6 *)addr;
	struct sockaddr_in *i4 = (struct sockaddr_in *)addr;
	char tmp[INET_ADDRSTRLEN + sizeof("[]:65535")];
	char *p, *q;
	int c;

	strncpy(tmp, str, sizeof(tmp) - 1);
	tmp[sizeof(tmp) - 1] = '\0';
	p = tmp;

	if (p[0] == '[') {
		p++;
		q = strchr(p, ']');
		if (!q)
			return -EINVAL;
		*q++ = '\0';
		if (q[0] != ':')
			return -EINVAL;
		c = atoi(q + 1);
		if (c < 1 || c > 65535)
			return -EINVAL;

		memset(i6, 0, sizeof(*i6));
		if (inet_pton(AF_INET6, p, &i6->sin6_addr) != 1) {
			fprintf(stderr, "Invalid IPv6 address: %s\n", p);
			return -EINVAL;
		}
		i6->sin6_family = AF_INET6;
		i6->sin6_port = htons(c);
		*addr_len = sizeof(*i6);
	} else {
		q = strchr(p, ':');
		if (!q)
			return -EINVAL;
		*q++ = '\0';
		c = atoi(q);
		if (c < 1 || c > 65535)
			return -EINVAL;

		memset(i4, 0, sizeof(*i4));
		if (inet_pton(AF_INET, p, &i4->sin_addr) != 1) {
			fprintf(stderr, "Invalid IPv4 address: %s\n", p);
			return -EINVAL;
		}
		i4->sin_family = AF_INET;
		i4->sin_port = htons(c);
		*addr_len = sizeof(*i4);
	}

	return 0;
}

static int gwc_srv_init(struct gwc_srv_ctx *ctx)
{
	int r = string_to_sockaddr(&ctx->bind_addr, &ctx->bind_addr_len,
				   ctx->cfg.bind_addr);
	if (r < 0)
		return r;

	r = gwc_srv_init_storage(ctx);
	if (r < 0)
		return r;

	r = gwc_srv_init_workers(ctx);
	if (r < 0) {
		gwc_srv_free_storage(ctx);
		return r;
	}

	return 0;
}

static void gwc_srv_free(struct gwc_srv_ctx *ctx)
{
	if (!ctx)
		return;

	gwc_srv_free_storage(ctx);
}

static int gwc_srv_run(struct gwc_srv_ctx *ctx)
{
	usleep(10000);
	return (int)(intptr_t)gwc_srv_worker_func(ctx->workers);
}

static int sock_set_nonblock(int fd, bool nonblock)
{
	int flags = fcntl(fd, F_GETFL);
	if (flags < 0)
		return -errno;

	if (nonblock)
		flags |= O_NONBLOCK;
	else
		flags &= ~O_NONBLOCK;

	if (fcntl(fd, F_SETFL, flags) < 0)
		return -errno;

	return 0;
}

static int gwc_cli_init_sock(struct gwc_cli_ctx *ctx)
{
	static const int flags = SOCK_CLOEXEC | SOCK_NONBLOCK | SOCK_STREAM;
	int fd, v = 1;
	socklen_t l = sizeof(v);

	fd = socket(ctx->server_addr.ss_family, flags, 0);
	if (fd < 0)
		return -errno;

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &v, l);
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &v, l);
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &v, l);
	setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &v, l);
	ctx->tcp_fd = fd;
	return 0;
}

static void gwc_cli_free_sock(struct gwc_cli_ctx *ctx)
{
	if (ctx->tcp_fd >= 0) {
		close(ctx->tcp_fd);
		ctx->tcp_fd = -1;
	}
}

static int gwc_cli_init(struct gwc_cli_ctx *ctx)
{
	int r = string_to_sockaddr(&ctx->server_addr,
				   &ctx->server_addr_len,
				   ctx->cfg.server_addr);
	if (r < 0)
		return r;

	r = gwc_cli_init_sock(ctx);
	if (r < 0) {
		fprintf(stderr, "Failed to initialize client socket: %s\n",
			strerror(-r));
		return r;
	}

	return 0;
}

static void gwc_cli_free(struct gwc_cli_ctx *ctx)
{
	if (!ctx)
		return;

	gwc_cli_free_sock(ctx);
	gwc_buf_free(&ctx->sn_buf);
}

static int gwc_cli_do_connect(struct gwc_cli_ctx *ctx)
{
	static const int timeout = 5000; /* 5 seconds. */
	struct pollfd pfd = { .fd = ctx->tcp_fd, .events = POLLOUT };
	struct sockaddr *addr = (struct sockaddr *)&ctx->server_addr;
	socklen_t len = ctx->server_addr_len;
	int r, err = 0;

	printf("Connecting to %s...\n", skaddr_to_str(&ctx->server_addr));
	r = connect(ctx->tcp_fd, addr, len);
	if (r < 0) {
		r = -errno;
		if (r != -EINPROGRESS)
			goto out_err;
	}

	r = poll(&pfd, 1, timeout);
	if (r < 0)
		return -errno;

	if (r == 0) {
		fprintf(stderr, "Connection timed out after %d ms.\n", timeout);
		return -ETIMEDOUT;
	}

	assert(pfd.revents & POLLOUT);
	len = sizeof(err);
	r = getsockopt(ctx->tcp_fd, SOL_SOCKET, SO_ERROR, &err, &len);
	if (r < 0) {
		r = -errno;
		fprintf(stderr, "Failed to get socket error: %s\n", strerror(-r));
		return r;
	}

	if (err) {
		r = -err;
		goto out_err;
	}

	return 0;

out_err:
	printf("Connection failed: %s\n", strerror(-r));
	return r;
}

static ssize_t gwc_cli_do_send_all(struct gwc_cli_ctx *ctx)
{
	ssize_t total_sent = 0;
	ssize_t ret;
	size_t len;
	char *buf;

repeat:
	if (ctx->stop)
		return -ECONNABORTED;

	len = ctx->sn_buf.len;
	buf = ctx->sn_buf.buf;
	ret = send(ctx->tcp_fd, buf, len, MSG_NOSIGNAL | MSG_WAITALL);
	if (ret < 0) {
		ret = -errno;
		if (ret == -EINTR)
			goto repeat;
		return ret;
	} else if (!ret) {
		return -ECONNRESET;
	}

	total_sent += ret;
	assert((size_t)ret <= len);
	gwc_buf_soft_advance(&ctx->sn_buf, (size_t)ret);
	if (ctx->sn_buf.len)
		goto repeat;

	return total_sent;
}

static ssize_t gwc_cli_do_recv_all(struct gwc_cli_ctx *ctx, size_t len_arg)
{
	ssize_t total_recv = 0;
	ssize_t ret;
	size_t len;
	char *buf;

repeat:
	buf = (char *)&ctx->rc_buf + ctx->rc_len;
	len = sizeof(ctx->rc_buf) - ctx->rc_len;
	assert(len >= len_arg);
	ret = recv(ctx->tcp_fd, buf, len_arg, MSG_NOSIGNAL | MSG_WAITALL);
	if (ret < 0) {
		ret = -errno;
		if (ret == -EINTR)
			goto repeat;
		fprintf(stderr, "Failed to receive data: %s\n", strerror(-ret));
		return ret;
	} else if (!ret) {
		return -ECONNRESET;
	}

	total_recv += ret;
	ctx->rc_len += (size_t)ret;
	assert((size_t)ret <= len);
	return total_recv;
}

static int gwc_cli_do_handshake(struct gwc_cli_ctx *ctx)
{
	static const size_t expected_len = sizeof(struct gwc_hdr_pkt) +
					   sizeof(struct gwc_pkt_hs);
	struct gwc_pkt *p, sp;
	ssize_t ret;
	size_t len;

	len = pkt_prep_conn_hs(&sp);
	ret = gwc_buf_append(&ctx->sn_buf, &sp, len);
	if (ret)
		return ret;

	printf("Sending connection handshake...\n");
	ret = gwc_cli_do_send_all(ctx);
	if (ret < 0)
		return ret;

	ret = gwc_cli_do_recv_all(ctx, expected_len);
	if (ret < 0)
		return ret;

	p = &ctx->rc_buf;
	p->hdr.len = be16toh(p->hdr.len);
	if (p->hdr.len != sizeof(p->conn.hs_ack)) {
		fprintf(stderr, "Invalid handshake response length: %hu\n",
			p->hdr.len);
		return -EINVAL;
	}

	if (memcmp(p->conn.hs_ack.magic, "gwchat01", 8)) {
		fprintf(stderr, "Invalid handshake response magic.\n");
		return -EINVAL;
	}

	printf("Handshake OK!\n");
	ctx->rc_len = 0;
	return 0;
}

static char *fgets_stdin_and_trim(char *buf, size_t size)
{
	size_t len;

	if (!fgets(buf, size, stdin))
		return NULL;

	len = strlen(buf);
	if (len > 0 && buf[len - 1] == '\n')
		buf[len - 1] = '\0';

	return buf;
}

static int gwc_cli_do_register_or_login(struct gwc_cli_ctx *ctx)
{
	struct gwc_cli_cfg *cfg = &ctx->cfg;
	struct gwc_pkt sp;
	ssize_t ret;
	size_t len;

	if (!cfg->uname[0]) {
		printf("%s username: ", cfg->do_register ? "Create" : "Login");
		if (!fgets_stdin_and_trim(cfg->uname, sizeof(cfg->uname)))
			return -EIO;
	}

	if (!cfg->pwd[0]) {
		printf("%s password: ", cfg->do_register ? "Create" : "Login");
		if (!fgets_stdin_and_trim(cfg->pwd, sizeof(cfg->pwd)))
			return -EIO;
	}

	if (cfg->do_register) {
		printf("Registering user '%s'...\n", cfg->uname);
		len = pkt_prep_acc_reg(&sp, cfg->uname, cfg->pwd);
	} else {
		printf("Logging in as user '%s'...\n", cfg->uname);
		len = pkt_prep_acc_login(&sp, cfg->uname, cfg->pwd);
	}

	ret = gwc_buf_append(&ctx->sn_buf, &sp, len);
	if (ret)
		return ret;

	ret = gwc_cli_do_send_all(ctx);
	if (ret < 0)
		return ret;

	return 0;
}

static int gwc_cli_run(struct gwc_cli_ctx *ctx)
{
	int r;

	r = gwc_cli_do_connect(ctx);
	if (r)
		return r;
	r = sock_set_nonblock(ctx->tcp_fd, false);
	if (r)
		return r;
	r = gwc_cli_do_handshake(ctx);
	if (r)
		return r;
	r = gwc_cli_do_register_or_login(ctx);
	if (r)
		return r;

	return 0;
}

noinline static int server_run(int argc, char *argv[])
{
	struct gwc_srv_ctx ctx;
	int r;

	memset(&ctx, 0, sizeof(ctx));
	r = server_parse_argv(argc, argv, &ctx);
	if (r < 0) {
		fprintf(stderr, "Failed to parse arguments: %s\n",
			strerror(-r));
		return r;
	}

	r = gwc_srv_init(&ctx);
	if (r < 0) {
		fprintf(stderr, "Failed to initialize server: %s\n",
			strerror(-r));
		return r;
	}

	r = gwc_srv_run(&ctx);
	gwc_srv_free(&ctx);
	return r;
}

noinline static int client_run(int argc, char *argv[])
{
	struct gwc_cli_ctx ctx;
	int r;

	memset(&ctx, 0, sizeof(ctx));
	r = client_parse_argv(argc, argv, &ctx);
	if (r < 0) {
		fprintf(stderr, "Failed to parse arguments: %s\n",
			strerror(-r));
		return r;
	}

	r = gwc_cli_init(&ctx);
	if (r < 0) {
		fprintf(stderr, "Failed to initialize client: %s\n",
			strerror(-r));
		return r;
	}

	r = gwc_cli_run(&ctx);
	gwc_cli_free(&ctx);
	return r;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <server|client> [options]\n", argv[0]);
		return EINVAL;
	}

	if (!strcmp(argv[1], "server")) {
		return server_run(argc, argv);
	} else if (!strcmp(argv[1], "client")) {
		return client_run(argc, argv);
	} else {
		fprintf(stderr, "Unknown mode: %s\n", argv[1]);
		return EINVAL;
	}

	return 0;
}

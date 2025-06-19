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

	GWC_PKT_CHAN_SUBSCRIBE		= 0x20,
	GWC_PKT_CHAN_UNSUBSCRIBE	= 0x21,
	GWC_PKT_CHAN_LIST		= 0x22,
	GWC_PKT_CHAN_LIST_MSG		= 0x23,
	GWC_PKT_CHAN_SEND_MSG		= 0x24,

	GWC_PKT_RESERVED		= 0xff,
};

struct gwc_pkt_hs {
	__u8	magic[8];
} __packed;

struct gwc_pkt_acc_udata {
	__u8	ulen;
	__u8	plen;
	__u8	__pad[6];
	char	data[];
} __packed;

struct gwc_pkt_chan_data {
	__be64	chan_id;
	__u8	nlen;
	char	data[];
} __packed;

struct gwc_pkt_chan_list {
	__be64 nr_chan;
	struct gwc_pkt_chan_data channels[];
};

struct gwc_hdr_pkt {
	__u8	type;
	__u8	flags;
	__be16	len;
} __packed;

struct gwc_pkt {
	struct gwc_hdr_pkt	hdr;
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
			__be64				subscribe;
			__be64				unsubscribe;
			struct gwc_pkt_chan_list	chan_list;
		} chan;

		char	__raw[4096 - 4];
	};
} __packed;

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

struct gwc_srv_cli {
	int			fd;
	struct gwc_user		*user;
	size_t			pkt_len;
	size_t			pkt_sn_len;
	union {
		struct gwc_pkt		pkt;
		char			__pkt_raw[sizeof(struct gwc_pkt)];
	};
	union {
		struct gwc_pkt		pkt_sn;
		char			__pkt_sn_raw[sizeof(struct gwc_pkt)];
	};
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
	{ NULL,			0,			NULL,	0 }
};
static const char client_opts[] = "hs:u:p:";

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

static int server_parse_argv(int argc, char *argv[], struct gwc_srv_ctx *ctx)
{
	size_t l;
	int c;

	ctx->cfg = default_srv_cfg;
	while (1) {
		c = getopt_long(argc - 1, argv + 1, server_opts, server_long_opts, NULL);
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

static int gwc_srv_realloc_cli_arr(struct gwc_srv_cli_arr *arr, uint32_t new_cap)
{
	struct gwc_srv_cli *new_clients;
	struct pollfd *new_pfd;
	uint32_t i, j;

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

	for (i = arr->nr; i < new_cap; i++) {
		j = i + 1;
		arr->clients[i].fd = -1;
		arr->pfd[j].fd = -1;
		arr->pfd[j].events = POLLIN | POLLRDHUP;
		arr->pfd[j].revents = 0;
	}
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
	int r;

	r = gwc_srv_resize_arr_if_needed(&w->cli_arr);
	if (r < 0)
		return r;

	r = gwc_srv_shrink_arr_if_reasonable(&w->cli_arr);
	if (r < 0)
		return r;

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
	struct gwc_pkt *p = &c->pkt;

	if (p->hdr.len != sizeof(p->conn.hs))
		return -EINVAL;

	if (memcmp(p->conn.hs.magic, "gwchat01", 8))
		return -EINVAL;

	if (!c->pkt_sn_len)
		c->pkt_sn_len = pkt_prep_conn_hs_ack(&c->pkt_sn);

	return gwc_srv_handle_event_send(w, c);
}

static int gwc_srv_handle_pkt_acc_reg(struct gwc_srv_wrk *w,
				      struct gwc_srv_cli *c)
{
	struct gwc_pkt_acc_udata *reg = &c->pkt.acc.reg;
	struct gwc_pkt *p = &c->pkt;
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
	switch (c->pkt.hdr.type) {
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
	p = &c->pkt;
	received_len = c->pkt_len;
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

	c->pkt_len -= expected_len;
	if (c->pkt_len) {
		memmove(&c->pkt, (char *)&c->pkt + expected_len, c->pkt_len);
		goto repeat;
	}

	return 0;
}

static int gwc_srv_handle_event_recv(struct gwc_srv_wrk *w,
				     struct gwc_srv_cli *c)
{
	ssize_t ret;
	size_t len;
	char *buf;

	buf = (char *)&c->pkt + c->pkt_len;
	len = sizeof(c->pkt) - c->pkt_len;
	ret = recv(c->fd, buf, len, MSG_NOSIGNAL);
	if (ret < 0) {
		ret = -errno;
		if (ret == -EAGAIN || ret == -EINTR)
			return 0;

		return ret;
	} else if (!ret) {
		return -ECONNRESET;
	}

	c->pkt_len += (size_t)ret;
	assert(c->pkt_len <= sizeof(c->pkt));
	return __gwc_srv_handle_event_recv(w, c);
}

static int gwc_srv_handle_event_send(struct gwc_srv_wrk *w,
				     struct gwc_srv_cli *c)
{
	ssize_t ret;
	size_t len;
	char *buf;

	len = c->pkt_sn_len;
	if (!len)
		return 0;

	buf = (char *)&c->pkt_sn;
	ret = send(c->fd, buf, len, MSG_NOSIGNAL | MSG_DONTWAIT);
	if (ret < 0) {
		ret = -errno;
		if (ret == -EAGAIN || ret == -EINTR)
			return 0;

		return ret;
	} else if (!ret) {
		return -ECONNRESET;
	}

	assert(ret <= (ssize_t)len);
	c->pkt_sn_len -= (size_t)ret;
	if (c->pkt_sn_len) {
		memmove(&c->pkt_sn, (char *)&c->pkt_sn + ret, c->pkt_sn_len);
	} else {
		if (c->pkt_len)
			return gwc_srv_handle_cli_pkt(w, c);
	}

	return 0;
}

static int gwc_srv_handle_event_close(struct gwc_srv_wrk *w, int i)
{
	struct gwc_srv_cli_arr *arr = &w->cli_arr;
	uint32_t last = w->cli_arr.nr;
	uint32_t idx = i + 1;

	close(arr->clients[i].fd);
	arr->pfd[idx] = arr->pfd[last];
	arr->clients[i] = arr->clients[last - 1];

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

	r = poll(w->cli_arr.pfd, w->cli_arr.nr + 1, 5000);
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

static int gwc_srv_prepare_bind_addr(struct gwc_srv_ctx *ctx)
{
	struct sockaddr_in6 *i6 = (struct sockaddr_in6 *)&ctx->bind_addr;
	struct sockaddr_in *i4 = (struct sockaddr_in *)&ctx->bind_addr;
	char tmp[INET_ADDRSTRLEN + sizeof("[]:65535")];
	char *p, *q;
	int c;

	strncpy(tmp, ctx->cfg.bind_addr, sizeof(tmp) - 1);
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
		ctx->bind_addr_len = sizeof(*i6);
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
		ctx->bind_addr_len = sizeof(*i4);
	}

	return 0;
}

static int gwc_srv_init(struct gwc_srv_ctx *ctx)
{
	int r = gwc_srv_prepare_bind_addr(ctx);
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
	return (int)(intptr_t)gwc_srv_worker_func(ctx->workers);
}

noinline static int server_run(int argc, char *argv[])
{
	struct gwc_srv_ctx ctx;
	int r;

	memset(&ctx, 0, sizeof(ctx));
	r = server_parse_argv(argc, argv, &ctx);
	if (r < 0) {
		fprintf(stderr, "Failed to parse arguments: %s\n", strerror(-r));
		return r;
	}

	r = gwc_srv_init(&ctx);
	if (r < 0) {
		fprintf(stderr, "Failed to initialize server: %s\n", strerror(-r));
		return r;
	}

	r = gwc_srv_run(&ctx);
	gwc_srv_free(&ctx);
	return r;
}

static int client_run(int argc, char *argv[])
{
	return 0;
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

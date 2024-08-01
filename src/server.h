#ifndef _SERVER_H
#define _SERVER_H

#include <time.h>
#include <libcork/ds.h>

#ifdef HAVE_LIBEV_EV_H
#include <libev/ev.h>
#else
#include <ev.h>
#endif

#include "crypto.h"
#include "jconf.h"
#include "netutils.h"

#include "common.h"

typedef struct listen_ctx {
    ev_io io;
    int fd;
    int timeout;
    char *iface;
    struct ev_loop *loop;
} listen_ctx_t;

typedef struct server_ctx {
    ev_io io;
    ev_timer watcher;
    int connected;
    struct server *server;
} server_ctx_t;

struct query;

typedef struct server {
    int fd;
    int stage;
    int frag;

    buffer_t *buf;

    cipher_ctx_t *e_ctx;
    cipher_ctx_t *d_ctx;
    struct server_ctx *recv_ctx;
    struct server_ctx *send_ctx;
    struct listen_ctx *listen_ctx;
    struct remote *remote;

    struct query *query;

    struct cork_dllist_item entries;
} server_t;

typedef struct query {
    server_t *server;
    char hostname[MAX_HOSTNAME_LEN];
} query_t;

typedef struct remote_ctx {
    ev_io io;
    int connected;
    struct remote *remote;
} remote_ctx_t;

typedef struct remote {
    int fd;
    buffer_t *buf;
    struct remote_ctx *recv_ctx;
    struct remote_ctx *send_ctx;
    struct server *server;
} remote_t;

static void signal_cb(EV_P_ ev_signal *w, int revents);
static void accept_cb(EV_P_ ev_io *w, int revents);
static void server_send_cb(EV_P_ ev_io *w, int revents);
static void server_recv_cb(EV_P_ ev_io *w, int revents);
static void remote_recv_cb(EV_P_ ev_io *w, int revents);
static void remote_send_cb(EV_P_ ev_io *w, int revents);
static void server_timeout_cb(EV_P_ ev_timer *watcher, int revents);
static void resolv_cb(struct sockaddr *addr, void *data);
static void resolv_free_cb(void *data);

static remote_t *new_remote(int fd);
static server_t *new_server(int fd, listen_ctx_t *listener);
static remote_t *connect_to_remote(EV_P_ struct addrinfo *res,
                                   server_t *server);

static void free_remote(remote_t *remote);
static void close_and_free_remote(EV_P_ remote_t *remote);
static void free_server(server_t *server);
static void close_and_free_server(EV_P_ server_t *server);

#endif // _SERVER_H

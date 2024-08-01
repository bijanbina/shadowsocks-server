#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <math.h>
#include <netdb.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/un.h>
#include <libcork/core.h>

#include "netutils.h"
#include "utils.h"
#include "server.h" 
#include "winsock.h" 
#include "resolv.h"

#ifndef SSMAXCONN
#define SSMAXCONN 1024
#endif

int verbose    = 0;
int reuse_port = 0;
int tcp_incoming_sndbuf = 0;
int tcp_incoming_rcvbuf = 0;
int tcp_outgoing_sndbuf = 0;
int tcp_outgoing_rcvbuf = 0;

int is_bind_local_addr = 0;
struct sockaddr_storage local_addr_v4;
struct sockaddr_storage local_addr_v6;

static crypto_t *crypto;

static int mode      = TCP_ONLY;
static int ipv6first = 0;
int fast_open        = 0;
static int no_delay  = 0;
static int ret_val   = 0;

static int remote_conn = 0;
static int server_conn = 0;

static char *remote_port  = NULL;
uint64_t tx               = 0;
uint64_t rx               = 0;

ev_timer stat_update_watcher;

static struct ev_signal sigint_watcher;
static struct ev_signal sigterm_watcher;
static struct ev_signal sigchld_watcher;

static struct cork_dllist connections;

static void
free_connections(struct ev_loop *loop)
{
    struct cork_dllist_item *curr, *next;
    cork_dllist_foreach_void(&connections, curr, next) {
        server_t *server = cork_container_of(curr, server_t, entries);
        remote_t *remote = server->remote;
        close_and_free_server(loop, server);
        close_and_free_remote(loop, remote);
    }
}

static void
stop_server(EV_P_ server_t *server)
{
    printf("STOPID\n");
    server->stage = STAGE_STOP;
}



int setnonblocking(int fd)
{
    int flags;
    if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
        flags = 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int create_and_bind(const char *host, const char *port, int mptcp)
{
    struct addrinfo hints;
    int s, listen_sock = -1;
    struct sockaddr_in servaddr; 

    memset(&hints, 0, sizeof(struct addrinfo));
	memset(&servaddr, 0, sizeof(servaddr));

    hints.ai_family   = AF_INET;       // IPv4 
    hints.ai_socktype = SOCK_STREAM ;  // We want a UDP socket SOCK_DGRAM
    hints.ai_flags    = AI_PASSIVE | AI_ADDRCONFIG; /* For wildcard IP address */
    hints.ai_protocol = IPPROTO_TCP;

	listen_sock = socket(hints.ai_family, hints.ai_socktype, hints.ai_protocol);
	if (listen_sock == -1) 
	{
		ERROR("bind");
		FATAL("failed to create listen socket");
    	return -1;
	}
        
    // Filling server information 
    servaddr.sin_family    = AF_INET; // IPv4 
    servaddr.sin_addr.s_addr = INADDR_ANY; 
    servaddr.sin_port = htons(atoi(port));

	s = bind(listen_sock, (struct sockaddr *)&servaddr, sizeof(struct sockaddr_in));
	if (s == 0)
	{
		/* We managed to bind successfully! */
    	return listen_sock;
	}
	else
	{
		ERROR("bind");
		FATAL("failed to bind address");
		close(listen_sock);
    	return -1;
	}

}

static remote_t *
connect_to_remote(EV_P_ struct addrinfo *res,
                  server_t *server)
{
    printf("CONNECT TO REMOTE : SAG1\n");
    int sockfd;

    // initialize remote socks
    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd == -1) {
        ERROR("socket");
        close(sockfd);
        return NULL;
    }

    int opt = 1;
    setsockopt(sockfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (tcp_outgoing_sndbuf > 0) {
        setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &tcp_outgoing_sndbuf, sizeof(int));
    }

    if (tcp_outgoing_rcvbuf > 0) {
        setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &tcp_outgoing_rcvbuf, sizeof(int));
    }

    // setup remote socks

    if (setnonblocking(sockfd) == -1)
        ERROR("setnonblocking");

    if (is_bind_local_addr) {
        struct sockaddr_storage *local_addr =
            res->ai_family == AF_INET ? &local_addr_v4 : &local_addr_v6;
        if (res->ai_family == local_addr->ss_family) {
            if (bind_to_addr(local_addr, sockfd) == -1) {
                ERROR("bind_to_addr");
                FATAL("cannot bind socket");
                return NULL;
            }
        }
    }

    remote_t *remote = new_remote(sockfd);

	int r = connect(sockfd, res->ai_addr, res->ai_addrlen);

	if (r == -1 && errno != CONNECT_IN_PROGRESS) {
            ERROR("connect");
            close_and_free_remote(EV_A_ remote);
            return NULL;
        }
    }

    return remote;
}

#ifdef USE_NFCONNTRACK_TOS
int
setMarkDscpCallback(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data)
{
    server_t *server            = (server_t *)data;
    struct dscptracker *tracker = server->tracker;

    tracker->mark = nfct_get_attr_u32(ct, ATTR_MARK);
    if ((tracker->mark & 0xff00) == MARK_MASK_PREFIX) {
        // Extract DSCP value from mark value
        tracker->dscp = tracker->mark & 0x00ff;
        int tos = (tracker->dscp) << 2;
        if (setsockopt(server->fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) != 0) {
            ERROR("iptable setsockopt IP_TOS");
        }
    }
    return NFCT_CB_CONTINUE;
}

void
conntrackQuery(server_t *server)
{
    struct dscptracker *tracker = server->tracker;
    if (tracker && tracker->ct) {
        // Trying query mark from nf conntrack
        struct nfct_handle *h = nfct_open(CONNTRACK, 0);
        if (h) {
            nfct_callback_register(h, NFCT_T_ALL, setMarkDscpCallback, (void *)server);
            int x = nfct_query(h, NFCT_Q_GET, tracker->ct);
            if (x == -1) {
                LOGE("QOS: Failed to retrieve connection mark %s", strerror(errno));
            }
            nfct_close(h);
        } else {
            LOGE("QOS: Failed to open conntrack handle for upstream netfilter mark retrieval.");
        }
    }
}

void
setTosFromConnmark(remote_t *remote, server_t *server)
{
    if (server->tracker && server->tracker->ct) {
        if (server->tracker->mark == 0 && server->tracker->packet_count < MARK_MAX_PACKET) {
            server->tracker->packet_count++;
            conntrackQuery(server);
        }
    } else {
        socklen_t len;
        struct sockaddr_storage sin;
        len = sizeof(sin);
        if (getpeername(remote->fd, (struct sockaddr *)&sin, &len) == 0) {
            struct sockaddr_storage from_addr;
            len = sizeof from_addr;
            if (getsockname(remote->fd, (struct sockaddr *)&from_addr, &len) == 0) {
                if ((server->tracker = (struct dscptracker *)ss_malloc(sizeof(struct dscptracker)))) {
                    if ((server->tracker->ct = nfct_new())) {
                        // Build conntrack query SELECT
                        if (from_addr.ss_family == AF_INET) {
                            struct sockaddr_in *src = (struct sockaddr_in *)&from_addr;
                            struct sockaddr_in *dst = (struct sockaddr_in *)&sin;

                            nfct_set_attr_u8(server->tracker->ct, ATTR_L3PROTO, AF_INET);
                            nfct_set_attr_u32(server->tracker->ct, ATTR_IPV4_DST, dst->sin_addr.s_addr);
                            nfct_set_attr_u32(server->tracker->ct, ATTR_IPV4_SRC, src->sin_addr.s_addr);
                            nfct_set_attr_u16(server->tracker->ct, ATTR_PORT_DST, dst->sin_port);
                            nfct_set_attr_u16(server->tracker->ct, ATTR_PORT_SRC, src->sin_port);
                        } else if (from_addr.ss_family == AF_INET6) {
                            struct sockaddr_in6 *src = (struct sockaddr_in6 *)&from_addr;
                            struct sockaddr_in6 *dst = (struct sockaddr_in6 *)&sin;

                            nfct_set_attr_u8(server->tracker->ct, ATTR_L3PROTO, AF_INET6);
                            nfct_set_attr(server->tracker->ct, ATTR_IPV6_DST, dst->sin6_addr.s6_addr);
                            nfct_set_attr(server->tracker->ct, ATTR_IPV6_SRC, src->sin6_addr.s6_addr);
                            nfct_set_attr_u16(server->tracker->ct, ATTR_PORT_DST, dst->sin6_port);
                            nfct_set_attr_u16(server->tracker->ct, ATTR_PORT_SRC, src->sin6_port);
                        }
                        nfct_set_attr_u8(server->tracker->ct, ATTR_L4PROTO, IPPROTO_TCP);
                        conntrackQuery(server);
                    } else {
                        LOGE("Failed to allocate new conntrack for upstream netfilter mark retrieval.");
                        server->tracker->ct = NULL;
                    }
                }
            }
        }
    }
}

#endif

static void
server_recv_cb(EV_P_ ev_io *w, int revents)
{
    server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
    server_t *server              = server_recv_ctx->server;
    remote_t *remote              = NULL;

    buffer_t *buf = server->buf;

    if (server->stage == STAGE_STREAM) {
        remote = server->remote;
        buf    = remote->buf;

        // Only timer the watcher if a valid connection is established
        ev_timer_again(EV_A_ & server->recv_ctx->watcher);
    }

    ssize_t r = recv(server->fd, buf->data, SOCKET_BUF_SIZE, 0);

    if (r == 0) {
        // connection closed
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else if (r == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            ERROR("server recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    // Ignore any new packet if the server is stopped
    if (server->stage == STAGE_STOP) {
        return;
    }

    tx      += r;
    buf->len = r;

    int err = crypto->decrypt(buf, server->d_ctx, SOCKET_BUF_SIZE);

    if (err == CRYPTO_ERROR) {
        report_addr(server->fd, "authentication error");
        stop_server(EV_A_ server);
        return;
    } else if (err == CRYPTO_NEED_MORE) {
        if (server->stage != STAGE_STREAM) {
            server->frag++;
        }
        return;
    }

    // handshake and transmit data
    if (server->stage == STAGE_STREAM) {
        int s = send(remote->fd, remote->buf->data, remote->buf->len, 0);
        if (s == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // no data, wait for send
                remote->buf->idx = 0;
                ev_io_stop(EV_A_ & server_recv_ctx->io);
                ev_io_start(EV_A_ & remote->send_ctx->io);
            } else {
                ERROR("server_recv_send");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
        } else if (s < remote->buf->len) {
            remote->buf->len -= s;
            remote->buf->idx  = s;
            ev_io_stop(EV_A_ & server_recv_ctx->io);
            ev_io_start(EV_A_ & remote->send_ctx->io);
        }
        return;
    } else if (server->stage == STAGE_INIT) {
        /*
         * Shadowsocks TCP Relay Header:
         *
         *    +------+----------+----------+
         *    | ATYP | DST.ADDR | DST.PORT |
         *    +------+----------+----------+
         *    |  1   | Variable |    2     |
         *    +------+----------+----------+
         *
         */

        int offset     = 0;
        int need_query = 0;
        char atyp      = server->buf->data[offset++];
        char host[255] = { 0 };
        uint16_t port  = 0;
        struct addrinfo info;
        struct sockaddr_storage storage;
        memset(&info, 0, sizeof(struct addrinfo));
        memset(&storage, 0, sizeof(struct sockaddr_storage));

        // get remote addr and port
        if ((atyp & ADDRTYPE_MASK) == 1) {
            // IP V4
            struct sockaddr_in *addr = (struct sockaddr_in *)&storage;
            size_t in_addr_len       = sizeof(struct in_addr);
            addr->sin_family = AF_INET;
            if (server->buf->len >= in_addr_len + 3) {
                memcpy(&addr->sin_addr, server->buf->data + offset, in_addr_len);
                inet_ntop(AF_INET, (const void *)(server->buf->data + offset),
                          host, INET_ADDRSTRLEN);
                offset += in_addr_len;
            } else {
                report_addr(server->fd, "invalid length for ipv4 address");
                stop_server(EV_A_ server);
                return;
            }
            memcpy(&addr->sin_port, server->buf->data + offset, sizeof(uint16_t));
            info.ai_family   = AF_INET;
            info.ai_socktype = SOCK_STREAM;
            info.ai_protocol = IPPROTO_TCP;
            info.ai_addrlen  = sizeof(struct sockaddr_in);
            info.ai_addr     = (struct sockaddr *)addr;
        } else if ((atyp & ADDRTYPE_MASK) == 3) {
            // Domain name
            uint8_t name_len = *(uint8_t *)(server->buf->data + offset);
            if (name_len + 4 <= server->buf->len) {
                memcpy(host, server->buf->data + offset + 1, name_len);
                offset += name_len + 1;
            } else {
                report_addr(server->fd, "invalid host name length");
                stop_server(EV_A_ server);
                return;
            }
            if (acl && outbound_block_match_host(host) == 1) {
                if (verbose)
                    LOGI("outbound blocked %s", host);
                close_and_free_server(EV_A_ server);
                return;
            }
            struct cork_ip ip;
            if (cork_ip_init(&ip, host) != -1) {
                info.ai_socktype = SOCK_STREAM;
                info.ai_protocol = IPPROTO_TCP;
                if (ip.version == 4) {
                    struct sockaddr_in *addr = (struct sockaddr_in *)&storage;
                    inet_pton(AF_INET, host, &(addr->sin_addr));
                    memcpy(&addr->sin_port, server->buf->data + offset, sizeof(uint16_t));
                    addr->sin_family = AF_INET;
                    info.ai_family   = AF_INET;
                    info.ai_addrlen  = sizeof(struct sockaddr_in);
                    info.ai_addr     = (struct sockaddr *)addr;
                } else if (ip.version == 6) {
                    struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&storage;
                    inet_pton(AF_INET6, host, &(addr->sin6_addr));
                    memcpy(&addr->sin6_port, server->buf->data + offset, sizeof(uint16_t));
                    addr->sin6_family = AF_INET6;
                    info.ai_family    = AF_INET6;
                    info.ai_addrlen   = sizeof(struct sockaddr_in6);
                    info.ai_addr      = (struct sockaddr *)addr;
                }
            } else {
                if (!validate_hostname(host, name_len)) {
                    report_addr(server->fd, "invalid host name");
                    stop_server(EV_A_ server);
                    return;
                }
                need_query = 1;
            }
        } else if ((atyp & ADDRTYPE_MASK) == 4) {
            // IP V6
            struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&storage;
            size_t in6_addr_len       = sizeof(struct in6_addr);
            addr->sin6_family = AF_INET6;
            if (server->buf->len >= in6_addr_len + 3) {
                memcpy(&addr->sin6_addr, server->buf->data + offset, in6_addr_len);
                inet_ntop(AF_INET6, (const void *)(server->buf->data + offset),
                          host, INET6_ADDRSTRLEN);
                offset += in6_addr_len;
            } else {
                LOGE("invalid header with addr type %d", atyp);
                report_addr(server->fd, "invalid length for ipv6 address");
                stop_server(EV_A_ server);
                return;
            }
            memcpy(&addr->sin6_port, server->buf->data + offset, sizeof(uint16_t));
            info.ai_family   = AF_INET6;
            info.ai_socktype = SOCK_STREAM;
            info.ai_protocol = IPPROTO_TCP;
            info.ai_addrlen  = sizeof(struct sockaddr_in6);
            info.ai_addr     = (struct sockaddr *)addr;
        }

        if (offset == 1) {
            report_addr(server->fd, "invalid address type");
            stop_server(EV_A_ server);
            return;
        }

        port = ntohs(load16_be(server->buf->data + offset));

        offset += 2;

        if (server->buf->len < offset) {
            report_addr(server->fd, "invalid request length");
            stop_server(EV_A_ server);
            return;
        } else {
            server->buf->len -= offset;
            server->buf->idx = offset;
        }

        if (verbose) {
            if ((atyp & ADDRTYPE_MASK) == 4)
                LOGI("[%s] connect to [%s]:%d", remote_port, host, ntohs(port));
            else
                LOGI("[%s] connect to %s:%d", remote_port, host, ntohs(port));
        }

        if (!need_query) {
            remote_t *remote = connect_to_remote(EV_A_ & info, server);

            if (remote == NULL) {
                LOGE("connect error");
                close_and_free_server(EV_A_ server);
                return;
            } else {
                server->remote = remote;
                remote->server = server;

                // XXX: should handle buffer carefully
                if (server->buf->len > 0) {
                    brealloc(remote->buf, server->buf->len, SOCKET_BUF_SIZE);
                    memcpy(remote->buf->data, server->buf->data + server->buf->idx,
                           server->buf->len);
                    remote->buf->len = server->buf->len;
                    remote->buf->idx = 0;
                    server->buf->len = 0;
                    server->buf->idx = 0;
                }

                // waiting on remote connected event
                ev_io_stop(EV_A_ & server_recv_ctx->io);
                ev_io_start(EV_A_ & remote->send_ctx->io);
            }
        } else {
            ev_io_stop(EV_A_ & server_recv_ctx->io);

            query_t *query = ss_malloc(sizeof(query_t));
            memset(query, 0, sizeof(query_t));
            query->server = server;
            server->query = query;
            snprintf(query->hostname, MAX_HOSTNAME_LEN, "%s", host);

            server->stage = STAGE_RESOLVE;
            resolv_start(host, port, resolv_cb, resolv_free_cb, query);
        }

        return;
    }
    // should not reach here
    FATAL("server context error");
}

static void
server_send_cb(EV_P_ ev_io *w, int revents)
{
    server_ctx_t *server_send_ctx = (server_ctx_t *)w;
    server_t *server              = server_send_ctx->server;
    remote_t *remote              = server->remote;

    if (remote == NULL) {
        LOGE("invalid server");
        close_and_free_server(EV_A_ server);
        return;
    }

    if (server->buf->len == 0) {
        // close and free
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(server->fd, server->buf->data + server->buf->idx,
                         server->buf->len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("server_send_send");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        } else if (s < server->buf->len) {
            // partly sent, move memory, wait for the next time to send
            server->buf->len -= s;
            server->buf->idx += s;
            return;
        } else {
            // all sent out, wait for reading
            server->buf->len = 0;
            server->buf->idx = 0;
            ev_io_stop(EV_A_ & server_send_ctx->io);
            if (remote != NULL) {
                ev_io_start(EV_A_ & remote->recv_ctx->io);
                return;
            } else {
                LOGE("invalid remote");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }
        }
    }
}

static void
server_timeout_cb(EV_P_ ev_timer *watcher, int revents)
{
    server_ctx_t *server_ctx
        = cork_container_of(watcher, server_ctx_t, watcher);
    server_t *server = server_ctx->server;
    remote_t *remote = server->remote;

    if (verbose) {
        LOGI("TCP connection timeout");
    }

    close_and_free_remote(EV_A_ remote);
    close_and_free_server(EV_A_ server);
}

static void
resolv_free_cb(void *data)
{
    query_t *query = (query_t *)data;

    if (query != NULL) {
        if (query->server != NULL)
            query->server->query = NULL;
        ss_free(query);
    }
}

static void
resolv_cb(struct sockaddr *addr, void *data)
{
    query_t *query   = (query_t *)data;
    server_t *server = query->server;

    if (server == NULL)
        return;

    struct ev_loop *loop = server->listen_ctx->loop;

    if (addr == NULL) {
        LOGE("unable to resolve %s", query->hostname);
        close_and_free_server(EV_A_ server);
    } else {
        if (verbose) {
            LOGI("successfully resolved %s", query->hostname);
        }

        struct addrinfo info;
        memset(&info, 0, sizeof(struct addrinfo));
        info.ai_socktype = SOCK_STREAM;
        info.ai_protocol = IPPROTO_TCP;
        info.ai_addr     = addr;

        if (addr->sa_family == AF_INET) {
            info.ai_family  = AF_INET;
            info.ai_addrlen = sizeof(struct sockaddr_in);
        } else if (addr->sa_family == AF_INET6) {
            info.ai_family  = AF_INET6;
            info.ai_addrlen = sizeof(struct sockaddr_in6);
        }

        remote_t *remote = connect_to_remote(EV_A_ & info, server);

        if (remote == NULL) {
            close_and_free_server(EV_A_ server);
        } else {
            server->remote = remote;
            remote->server = server;

            // XXX: should handle buffer carefully
            if (server->buf->len > 0) {
                brealloc(remote->buf, server->buf->len, SOCKET_BUF_SIZE);
                memcpy(remote->buf->data, server->buf->data + server->buf->idx,
                       server->buf->len);
                remote->buf->len = server->buf->len;
                remote->buf->idx = 0;
                server->buf->len = 0;
                server->buf->idx = 0;
            }

            // listen to remote connected event
            ev_io_start(EV_A_ & remote->send_ctx->io);
        }
    }
}

static void
remote_recv_cb(EV_P_ ev_io *w, int revents)
{
    remote_ctx_t *remote_recv_ctx = (remote_ctx_t *)w;
    remote_t *remote              = remote_recv_ctx->remote;
    server_t *server              = remote->server;

    if (server == NULL) {
        LOGE("invalid server");
        close_and_free_remote(EV_A_ remote);
        return;
    }

    ev_timer_again(EV_A_ & server->recv_ctx->watcher);

    ssize_t r = recv(remote->fd, server->buf->data, SOCKET_BUF_SIZE, 0);

    if (r == 0) {
        // connection closed
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else if (r == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            ERROR("remote recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    rx += r;

    // Ignore any new packet if the server is stopped
    if (server->stage == STAGE_STOP) {
        return;
    }

    server->buf->len = r;
    int err = crypto->encrypt(server->buf, server->e_ctx, SOCKET_BUF_SIZE);

    if (err) {
        LOGE("invalid password or cipher");
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    }

#ifdef USE_NFCONNTRACK_TOS
    setTosFromConnmark(remote, server);
#endif
    int s = send(server->fd, server->buf->data, server->buf->len, 0);

    if (s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            server->buf->idx = 0;
            ev_io_stop(EV_A_ & remote_recv_ctx->io);
            ev_io_start(EV_A_ & server->send_ctx->io);
        } else {
            ERROR("remote_recv_send");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    } else if (s < server->buf->len) {
        server->buf->len -= s;
        server->buf->idx  = s;
        ev_io_stop(EV_A_ & remote_recv_ctx->io);
        ev_io_start(EV_A_ & server->send_ctx->io);
    }

    // Disable TCP_NODELAY after the first response are sent
    if (!remote->recv_ctx->connected && !no_delay) {
        int opt = 0;
        setsockopt(server->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
        setsockopt(remote->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
    }
    remote->recv_ctx->connected = 1;
}

static void
remote_send_cb(EV_P_ ev_io *w, int revents)
{
    remote_ctx_t *remote_send_ctx = (remote_ctx_t *)w;
    remote_t *remote              = remote_send_ctx->remote;
    server_t *server              = remote->server;

    if (server == NULL) {
        LOGE("invalid server");
        close_and_free_remote(EV_A_ remote);
        return;
    }

    if (!remote_send_ctx->connected) {
#ifdef TCP_FASTOPEN_WINSOCK
        if (fast_open) {
            // Check if ConnectEx is done
            if (!remote->connect_ex_done) {
                DWORD numBytes;
                DWORD flags;
                // Non-blocking way to fetch ConnectEx result
                if (WSAGetOverlappedResult(remote->fd, &remote->olap,
                                           &numBytes, FALSE, &flags)) {
                    remote->buf->len       -= numBytes;
                    remote->buf->idx        = numBytes;
                    remote->connect_ex_done = 1;
                } else if (WSAGetLastError() == WSA_IO_INCOMPLETE) {
                    // XXX: ConnectEx still not connected, wait for next time
                    return;
                } else {
                    ERROR("WSAGetOverlappedResult");
                    // not connected
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                    return;
                }
            }

            // Make getpeername work
            if (setsockopt(remote->fd, SOL_SOCKET,
                           SO_UPDATE_CONNECT_CONTEXT, NULL, 0) != 0) {
                ERROR("setsockopt");
            }
        }
#endif
        struct sockaddr_storage addr;
        socklen_t len = sizeof(struct sockaddr_storage);
        memset(&addr, 0, len);

        int r = getpeername(remote->fd, (struct sockaddr *)&addr, &len);

        if (r == 0) {
            remote_send_ctx->connected = 1;

            if (remote->buf->len == 0) {
                server->stage = STAGE_STREAM;
                ev_io_stop(EV_A_ & remote_send_ctx->io);
                ev_io_start(EV_A_ & server->recv_ctx->io);
                ev_io_start(EV_A_ & remote->recv_ctx->io);
                return;
            }
        } else {
            ERROR("getpeername");
            // not connected
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    if (remote->buf->len == 0) {
        // close and free
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(remote->fd, remote->buf->data + remote->buf->idx,
                         remote->buf->len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("remote_send_send");
                // close and free
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        } else if (s < remote->buf->len) {
            // partly sent, move memory, wait for the next time to send
            remote->buf->len -= s;
            remote->buf->idx += s;
            return;
        } else {
            // all sent out, wait for reading
            remote->buf->len = 0;
            remote->buf->idx = 0;
            ev_io_stop(EV_A_ & remote_send_ctx->io);
            if (server != NULL) {
                ev_io_start(EV_A_ & server->recv_ctx->io);
                if (server->stage != STAGE_STREAM) {
                    server->stage = STAGE_STREAM;
                    ev_io_start(EV_A_ & remote->recv_ctx->io);
                }
            } else {
                LOGE("invalid server");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        }
    }
}

static remote_t *
new_remote(int fd)
{
    if (verbose) {
        remote_conn++;
        LOGI("new connection to remote, %d opened remote connections", remote_conn);
    }

    remote_t *remote = ss_malloc(sizeof(remote_t));
    memset(remote, 0, sizeof(remote_t));

    remote->recv_ctx = ss_malloc(sizeof(remote_ctx_t));
    remote->send_ctx = ss_malloc(sizeof(remote_ctx_t));
    remote->buf      = ss_malloc(sizeof(buffer_t));
    balloc(remote->buf, SOCKET_BUF_SIZE);
    memset(remote->recv_ctx, 0, sizeof(remote_ctx_t));
    memset(remote->send_ctx, 0, sizeof(remote_ctx_t));
    remote->fd                  = fd;
    remote->recv_ctx->remote    = remote;
    remote->recv_ctx->connected = 0;
    remote->send_ctx->remote    = remote;
    remote->send_ctx->connected = 0;
    remote->server              = NULL;

    ev_io_init(&remote->recv_ctx->io, remote_recv_cb, fd, EV_READ);
    ev_io_init(&remote->send_ctx->io, remote_send_cb, fd, EV_WRITE);

    return remote;
}

static void
free_remote(remote_t *remote)
{
    if (remote->server != NULL) {
        remote->server->remote = NULL;
    }
    if (remote->buf != NULL) {
        bfree(remote->buf);
        ss_free(remote->buf);
    }
    ss_free(remote->recv_ctx);
    ss_free(remote->send_ctx);
    ss_free(remote);
}

static void
close_and_free_remote(EV_P_ remote_t *remote)
{
    if (remote != NULL) {
        ev_io_stop(EV_A_ & remote->send_ctx->io);
        ev_io_stop(EV_A_ & remote->recv_ctx->io);
        close(remote->fd);
        free_remote(remote);
        if (verbose) {
            remote_conn--;
            LOGI("close a connection to remote, %d opened remote connections", remote_conn);
        }
    }
}

static server_t *
new_server(int fd, listen_ctx_t *listener)
{
    if (verbose) {
        server_conn++;
        LOGI("new connection from client, %d opened client connections", server_conn);
    }

    server_t *server;
    server = ss_malloc(sizeof(server_t));

    memset(server, 0, sizeof(server_t));

    server->recv_ctx = ss_malloc(sizeof(server_ctx_t));
    server->send_ctx = ss_malloc(sizeof(server_ctx_t));
    server->buf      = ss_malloc(sizeof(buffer_t));
    memset(server->recv_ctx, 0, sizeof(server_ctx_t));
    memset(server->send_ctx, 0, sizeof(server_ctx_t));
    balloc(server->buf, SOCKET_BUF_SIZE);
    server->fd                  = fd;
    server->recv_ctx->server    = server;
    server->recv_ctx->connected = 0;
    server->send_ctx->server    = server;
    server->send_ctx->connected = 0;
    server->stage               = STAGE_INIT;
    server->frag                = 0;
    server->query               = NULL;
    server->listen_ctx          = listener;
    server->remote              = NULL;

    server->e_ctx = ss_malloc(sizeof(cipher_ctx_t));
    server->d_ctx = ss_malloc(sizeof(cipher_ctx_t));
    crypto->ctx_init(crypto->cipher, server->e_ctx, 1);
    crypto->ctx_init(crypto->cipher, server->d_ctx, 0);

    int timeout = max(MIN_TCP_IDLE_TIMEOUT, server->listen_ctx->timeout);
    ev_io_init(&server->recv_ctx->io, server_recv_cb, fd, EV_READ);
    ev_io_init(&server->send_ctx->io, server_send_cb, fd, EV_WRITE);
    ev_timer_init(&server->recv_ctx->watcher, server_timeout_cb,
                  timeout, timeout);

    cork_dllist_add(&connections, &server->entries);

    return server;
}

static void
free_server(server_t *server)
{
#ifdef USE_NFCONNTRACK_TOS
    if (server->tracker) {
        struct dscptracker *tracker = server->tracker;
        struct nf_conntrack *ct     = server->tracker->ct;
        server->tracker = NULL;
        if (ct) {
            nfct_destroy(ct);
        }
        free(tracker);
    }
#endif
    cork_dllist_remove(&server->entries);

    if (server->remote != NULL) {
        server->remote->server = NULL;
    }
    if (server->e_ctx != NULL) {
        crypto->ctx_release(server->e_ctx);
        ss_free(server->e_ctx);
    }
    if (server->d_ctx != NULL) {
        crypto->ctx_release(server->d_ctx);
        ss_free(server->d_ctx);
    }
    if (server->buf != NULL) {
        bfree(server->buf);
        ss_free(server->buf);
    }

    ss_free(server->recv_ctx);
    ss_free(server->send_ctx);
    ss_free(server);
}

static void
close_and_free_server(EV_P_ server_t *server)
{
    if (server != NULL) {
        if (server->query != NULL) {
            server->query->server = NULL;
            server->query         = NULL;
        }
        ev_io_stop(EV_A_ & server->send_ctx->io);
        ev_io_stop(EV_A_ & server->recv_ctx->io);
        ev_timer_stop(EV_A_ & server->recv_ctx->watcher);
        close(server->fd);
        free_server(server);
        if (verbose) {
            server_conn--;
            LOGI("close a connection from client, %d opened client connections", server_conn);
        }
    }
}

static void
signal_cb(EV_P_ ev_signal *w, int revents)
{
    if (revents & EV_SIGNAL) {
        switch (w->signum) {
#ifndef __MINGW32__
        case SIGCHLD:
            if (!is_plugin_running()) {
                LOGE("plugin service exit unexpectedly");
                ret_val = -1;
            } else
                return;
#endif
        case SIGINT:
        case SIGTERM:
            ev_signal_stop(EV_DEFAULT, &sigint_watcher);
            ev_signal_stop(EV_DEFAULT, &sigterm_watcher);
#ifndef __MINGW32__
            ev_signal_stop(EV_DEFAULT, &sigchld_watcher);
#else
            ev_io_stop(EV_DEFAULT, &plugin_watcher.io);
#endif
            ev_unloop(EV_A_ EVUNLOOP_ALL);
        }
    }
}

#ifdef __MINGW32__
static void
plugin_watcher_cb(EV_P_ ev_io *w, int revents)
{
    char buf[1];
    SOCKET fd = accept(plugin_watcher.fd, NULL, NULL);
    if (fd == INVALID_SOCKET) {
        return;
    }
    recv(fd, buf, 1, 0);
    closesocket(fd);
    LOGE("plugin service exit unexpectedly");
    ret_val = -1;
    ev_signal_stop(EV_DEFAULT, &sigint_watcher);
    ev_signal_stop(EV_DEFAULT, &sigterm_watcher);
    ev_io_stop(EV_DEFAULT, &plugin_watcher.io);
    ev_unloop(EV_A_ EVUNLOOP_ALL);
}

#endif

static void
accept_cb(EV_P_ ev_io *w, int revents)
{
    listen_ctx_t *listener = (listen_ctx_t *)w;
    int serverfd           = accept(listener->fd, NULL, NULL);
    if (serverfd == -1) {
        ERROR("accept");
        return;
    }

    char *peer_name = get_peer_name(serverfd);
    if (peer_name != NULL) {
        if (acl) {
            if ((get_acl_mode() == BLACK_LIST && acl_match_host(peer_name) == 1)
                || (get_acl_mode() == WHITE_LIST && acl_match_host(peer_name) >= 0)) {
                LOGE("Access denied from %s", peer_name);
                close(serverfd);
                return;
            }
        }
    }

    int opt = 1;
    setsockopt(serverfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(serverfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    if (tcp_incoming_sndbuf > 0) {
        setsockopt(serverfd, SOL_SOCKET, SO_SNDBUF, &tcp_incoming_sndbuf, sizeof(int));
    }

    if (tcp_incoming_rcvbuf > 0) {
        setsockopt(serverfd, SOL_SOCKET, SO_RCVBUF, &tcp_incoming_rcvbuf, sizeof(int));
    }

    setnonblocking(serverfd);

    server_t *server = new_server(serverfd, listener);
    ev_io_start(EV_A_ & server->recv_ctx->io);
    ev_timer_start(EV_A_ & server->recv_ctx->watcher);
}

int
main(int argc, char **argv)
{
    int i, c;
    int pid_flags   = 0;
    int mptcp       = 0;
    int mtu         = 0;
    char *user      = NULL;
    char *password  = NULL;
    char *key       = NULL;
    char *timeout   = NULL;
    char *method    = NULL;
    char *pid_path  = NULL;
    char *conf_path = NULL;
    char *iface     = NULL;

    char *server_port = NULL;
    char *plugin_opts = NULL;
    char *plugin_host = NULL;
    char *plugin_port = NULL;
    char tmp_port[8];
    char *nameservers = NULL;

    int server_num = 0;
    ss_addr_t server_addr[MAX_REMOTE_NUM];
    memset(server_addr, 0, sizeof(ss_addr_t) * MAX_REMOTE_NUM);
    memset(&local_addr_v4, 0, sizeof(struct sockaddr_storage));
    memset(&local_addr_v6, 0, sizeof(struct sockaddr_storage));

    static struct option long_options[] = {
        { "fast-open",       no_argument,       NULL, GETOPT_VAL_FAST_OPEN   },
        { "reuse-port",      no_argument,       NULL, GETOPT_VAL_REUSE_PORT  },
        { "tcp-incoming-sndbuf", required_argument, NULL, GETOPT_VAL_TCP_INCOMING_SNDBUF },
        { "tcp-incoming-rcvbuf", required_argument, NULL, GETOPT_VAL_TCP_INCOMING_RCVBUF },
        { "tcp-outgoing-sndbuf", required_argument, NULL, GETOPT_VAL_TCP_OUTGOING_SNDBUF },
        { "tcp-outgoing-rcvbuf", required_argument, NULL, GETOPT_VAL_TCP_OUTGOING_RCVBUF },
        { "no-delay",        no_argument,       NULL, GETOPT_VAL_NODELAY     },
        { "acl",             required_argument, NULL, GETOPT_VAL_ACL         },
        { "manager-address", required_argument, NULL,
          GETOPT_VAL_MANAGER_ADDRESS },
        { "mtu",             required_argument, NULL, GETOPT_VAL_MTU         },
        { "help",            no_argument,       NULL, GETOPT_VAL_HELP        },
        { "plugin",          required_argument, NULL, GETOPT_VAL_PLUGIN      },
        { "plugin-opts",     required_argument, NULL, GETOPT_VAL_PLUGIN_OPTS },
        { "password",        required_argument, NULL, GETOPT_VAL_PASSWORD    },
        { "key",             required_argument, NULL, GETOPT_VAL_KEY         },
#ifdef __linux__
        { "mptcp",           no_argument,       NULL, GETOPT_VAL_MPTCP       },
#ifdef USE_NFTABLES
        { "nftables-sets",   required_argument, NULL, GETOPT_VAL_NFTABLES_SETS },
#endif
#endif
        { NULL,              0,                 NULL, 0                      }
    };

    opterr = 0;

    USE_TTY();

    while ((c = getopt_long(argc, argv, "f:s:p:l:k:t:m:b:c:i:d:a:n:huUv6A",
                            long_options, NULL)) != -1) {
        switch (c) {
        case GETOPT_VAL_FAST_OPEN:
            fast_open = 1;
            break;
        case GETOPT_VAL_NODELAY:
            no_delay = 1;
            LOGI("enable TCP no-delay");
            break;
        case GETOPT_VAL_ACL:
            LOGI("initializing acl...");
            acl = !init_acl(optarg);
            break;
        case GETOPT_VAL_MANAGER_ADDRESS:
            manager_addr = optarg;
            break;
        case GETOPT_VAL_MTU:
            mtu = atoi(optarg);
            LOGI("set MTU to %d", mtu);
            break;
        case GETOPT_VAL_PLUGIN:
            plugin = optarg;
            break;
        case GETOPT_VAL_PLUGIN_OPTS:
            plugin_opts = optarg;
            break;
        case GETOPT_VAL_MPTCP:
            mptcp = get_mptcp(1);
            if (mptcp)
                LOGI("enable multipath TCP (%s)", mptcp > 0 ? "out-of-tree" : "upstream");
            break;
        case GETOPT_VAL_KEY:
            key = optarg;
            break;
        case GETOPT_VAL_REUSE_PORT:
            reuse_port = 1;
            break;
        case GETOPT_VAL_TCP_INCOMING_SNDBUF:
            tcp_incoming_sndbuf = atoi(optarg);
            break;
        case GETOPT_VAL_TCP_INCOMING_RCVBUF:
            tcp_incoming_rcvbuf = atoi(optarg);
            break;
        case GETOPT_VAL_TCP_OUTGOING_SNDBUF:
            tcp_outgoing_sndbuf = atoi(optarg);
            break;
        case GETOPT_VAL_TCP_OUTGOING_RCVBUF:
            tcp_outgoing_rcvbuf = atoi(optarg);
            break;
#ifdef USE_NFTABLES
        case GETOPT_VAL_NFTABLES_SETS:
            nftbl_init(optarg);
            break;
#endif
        case 's':
            if (server_num < MAX_REMOTE_NUM) {
                parse_addr(optarg, &server_addr[server_num++]);
            }
            break;
        case 'b':
            is_bind_local_addr += parse_local_addr(&local_addr_v4, &local_addr_v6, optarg);
            break;
        case 'p':
            server_port = optarg;
            break;
        case GETOPT_VAL_PASSWORD:
        case 'k':
            password = optarg;
            break;
        case 'f':
            pid_flags = 1;
            pid_path  = optarg;
            break;
        case 't':
            timeout = optarg;
            break;
        case 'm':
            method = optarg;
            break;
        case 'c':
            conf_path = optarg;
            break;
        case 'i':
            iface = optarg;
            break;
        case 'd':
            nameservers = optarg;
            break;
        case 'a':
            user = optarg;
            break;
#ifdef HAVE_SETRLIMIT
        case 'n':
            nofile = atoi(optarg);
            break;
#endif
        case 'u':
            mode = TCP_AND_UDP;
            break;
        case 'U':
            mode = UDP_ONLY;
            break;
        case 'v':
            verbose = 1;
            break;
        case GETOPT_VAL_HELP:
        case 'h':
            usage();
            exit(EXIT_SUCCESS);
        case '6':
            ipv6first = 1;
            break;
        case 'A':
            FATAL("One time auth has been deprecated. Try AEAD ciphers instead.");
            break;
        case '?':
            // The option character is not recognized.
            LOGE("Unrecognized option: %s", optarg);
            opterr = 1;
            break;
        }
    }

    if (opterr) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (argc == 1) {
        if (conf_path == NULL) {
            conf_path = get_default_conf();
        }
    }

    if (conf_path != NULL) {
        jconf_t *conf = read_jconf(conf_path);
        if (server_num == 0) {
            server_num = conf->remote_num;
            for (i = 0; i < server_num; i++)
                server_addr[i] = conf->remote_addr[i];
        }
        if (server_port == NULL) {
            server_port = conf->remote_port;
        }
        if (password == NULL) {
            password = conf->password;
        }
        if (key == NULL) {
            key = conf->key;
        }
        if (method == NULL) {
            method = conf->method;
        }
        if (timeout == NULL) {
            timeout = conf->timeout;
        }
        if (user == NULL) {
            user = conf->user;
        }
        if (plugin == NULL) {
            plugin = conf->plugin;
        }
        if (plugin_opts == NULL) {
            plugin_opts = conf->plugin_opts;
        }
        if (mode == TCP_ONLY) {
            mode = conf->mode;
        }
        if (mtu == 0) {
            mtu = conf->mtu;
        }
        if (mptcp == 0) {
            mptcp = conf->mptcp;
        }
        if (no_delay == 0) {
            no_delay = conf->no_delay;
        }
        if (reuse_port == 0) {
            reuse_port = conf->reuse_port;
        }
        if (tcp_incoming_sndbuf == 0) {
            tcp_incoming_sndbuf = conf->tcp_incoming_sndbuf;
        }
        if (tcp_incoming_rcvbuf == 0) {
            tcp_incoming_rcvbuf = conf->tcp_incoming_rcvbuf;
        }
        if (tcp_outgoing_sndbuf == 0) {
            tcp_outgoing_sndbuf = conf->tcp_outgoing_sndbuf;
        }
        if (tcp_outgoing_rcvbuf == 0) {
            tcp_outgoing_rcvbuf = conf->tcp_outgoing_rcvbuf;
        }
        if (fast_open == 0) {
            fast_open = conf->fast_open;
        }
        if (is_bind_local_addr == 0) {
            is_bind_local_addr += parse_local_addr(&local_addr_v4, &local_addr_v6, conf->local_addr);
        }
        if (is_bind_local_addr == 0) {
            is_bind_local_addr += parse_local_addr(&local_addr_v4, &local_addr_v6, conf->local_addr_v4);
            is_bind_local_addr += parse_local_addr(&local_addr_v4, &local_addr_v6, conf->local_addr_v6);
        }
#ifdef HAVE_SETRLIMIT
        if (nofile == 0) {
            nofile = conf->nofile;
        }
#endif
        if (nameservers == NULL) {
            nameservers = conf->nameserver;
        }
        if (ipv6first == 0) {
            ipv6first = conf->ipv6_first;
        }
        if (acl == 0 && conf->acl != NULL) {
            LOGI("initializing acl...");
            acl = !init_acl(conf->acl);
        }
    }

    if (tcp_incoming_sndbuf != 0 && tcp_incoming_sndbuf < SOCKET_BUF_SIZE) {
        tcp_incoming_sndbuf = 0;
    }

    if (tcp_incoming_sndbuf != 0) {
        LOGI("set TCP incoming connection send buffer size to %d", tcp_incoming_sndbuf);
    }

    if (tcp_incoming_rcvbuf != 0 && tcp_incoming_rcvbuf < SOCKET_BUF_SIZE) {
        tcp_incoming_rcvbuf = 0;
    }

    if (tcp_incoming_rcvbuf != 0) {
        LOGI("set TCP incoming connection receive buffer size to %d", tcp_incoming_rcvbuf);
    }

    if (tcp_outgoing_sndbuf != 0 && tcp_outgoing_sndbuf < SOCKET_BUF_SIZE) {
        tcp_outgoing_sndbuf = 0;
    }

    if (tcp_outgoing_sndbuf != 0) {
        LOGI("set TCP outgoing connection send buffer size to %d", tcp_outgoing_sndbuf);
    }

    if (tcp_outgoing_rcvbuf != 0 && tcp_outgoing_rcvbuf < SOCKET_BUF_SIZE) {
        tcp_outgoing_rcvbuf = 0;
    }

    if (tcp_outgoing_rcvbuf != 0) {
        LOGI("set TCP outgoing connection receive buffer size to %d", tcp_outgoing_rcvbuf);
    }

    if (server_num == 0) {
        server_addr[server_num++].host = "0.0.0.0";
    }

    if (server_num == 0 || server_port == NULL
        || (password == NULL && key == NULL)) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (is_ipv6only(server_addr, server_num, ipv6first)) {
        plugin_host = "::1";
    } else {
        plugin_host = "127.0.0.1";
    }

    remote_port = server_port;

#ifdef __MINGW32__
    winsock_init();
#endif

    if (plugin != NULL) {
        uint16_t port = get_local_port();
        if (port == 0) {
            FATAL("failed to find a free port");
        }
        snprintf(tmp_port, 8, "%d", port);
        plugin_port = server_port;
        server_port = tmp_port;

#ifdef __MINGW32__
        memset(&plugin_watcher, 0, sizeof(plugin_watcher));
        plugin_watcher.port = get_local_port();
        if (plugin_watcher.port == 0) {
            LOGE("failed to assign a control port for plugin");
        }
#endif
    }

    if (method == NULL) {
        method = "chacha20-ietf-poly1305";
    }

    if (timeout == NULL) {
        timeout = "60";
    }

#ifdef HAVE_SETRLIMIT
    /*
     * no need to check the return value here since we will show
     * the user an error message if setrlimit(2) fails
     */
    if (nofile > 1024) {
        if (verbose) {
            LOGI("setting NOFILE to %d", nofile);
        }
        set_nofile(nofile);
    }
#endif

    USE_SYSLOG(argv[0], pid_flags);
    if (pid_flags) {
        daemonize(pid_path);
    }

    if (ipv6first) {
        LOGI("resolving hostname to IPv6 address first");
    }

    if (fast_open == 1) {
#ifdef TCP_FASTOPEN
        LOGI("using tcp fast open");
#else
        LOGE("tcp fast open is not supported by this environment");
        fast_open = 0;
#endif
    }

    if (plugin != NULL) {
        LOGI("plugin \"%s\" enabled", plugin);
    }

    if (mode != TCP_ONLY) {
        LOGI("UDP relay enabled");
    }

    if (mode == UDP_ONLY) {
        LOGI("TCP relay disabled");
    }

    if (no_delay) {
        LOGI("enable TCP no-delay");
    }

#ifndef __MINGW32__
    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);
#endif

    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_start(EV_DEFAULT, &sigint_watcher);
    ev_signal_start(EV_DEFAULT, &sigterm_watcher);
#ifndef __MINGW32__
    ev_signal_init(&sigchld_watcher, signal_cb, SIGCHLD);
    ev_signal_start(EV_DEFAULT, &sigchld_watcher);
#endif

    // setup keys
    LOGI("initializing ciphers... %s", method);
    crypto = crypto_init(password, key, method);
    if (crypto == NULL)
        FATAL("failed to initialize ciphers");

    // initialize ev loop
    struct ev_loop *loop = EV_DEFAULT;

    // setup dns
    resolv_init(loop, nameservers, ipv6first);

    if (nameservers != NULL)
        LOGI("using nameserver: %s", nameservers);

#ifdef __MINGW32__
    // Listen on plugin control port
    if (plugin != NULL && plugin_watcher.port != 0) {
        SOCKET fd;
        fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fd != INVALID_SOCKET) {
            plugin_watcher.valid = 0;
            do {
                struct sockaddr_in addr;
                memset(&addr, 0, sizeof(addr));
                addr.sin_family      = AF_INET;
                addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                addr.sin_port        = htons(plugin_watcher.port);
                if (bind(fd, (struct sockaddr *)&addr, sizeof(addr))) {
                    LOGE("failed to bind plugin control port");
                    break;
                }
                if (listen(fd, 1)) {
                    LOGE("failed to listen on plugin control port");
                    break;
                }
                plugin_watcher.fd = fd;
                ev_io_init(&plugin_watcher.io, plugin_watcher_cb, fd, EV_READ);
                ev_io_start(EV_DEFAULT, &plugin_watcher.io);
                plugin_watcher.valid = 1;
            } while (0);
            if (!plugin_watcher.valid) {
                closesocket(fd);
                plugin_watcher.port = 0;
            }
        }
    }
#endif

    // Start plugin server
    if (plugin != NULL) {
        int len          = 0;
        size_t buf_size  = 256 * server_num;
        char *server_str = ss_malloc(buf_size);

        snprintf(server_str, buf_size, "%s", server_addr[0].host);
        len = strlen(server_str);
        for (int i = 1; i < server_num; i++) {
            snprintf(server_str + len, buf_size - len, "|%s", server_addr[i].host);
            len = strlen(server_str);
        }

        int err = start_plugin(plugin, plugin_opts, server_str,
                               plugin_port, plugin_host, server_port,
#ifdef __MINGW32__
                               plugin_watcher.port,
#endif
                               MODE_SERVER);
        if (err) {
            ERROR("start_plugin");
            FATAL("failed to start the plugin");
        }
    }

    // initialize listen context
    listen_ctx_t listen_ctx_list[server_num];

    // bind to each interface
    if (mode != UDP_ONLY) {
        int num_listen_ctx = 0;
        for (int i = 0; i < server_num; i++) {
            const char *host = server_addr[i].host;
            const char *port = server_addr[i].port ? server_addr[i].port : server_port;

            if (plugin != NULL) {
                host = plugin_host;
            }

            if (host && ss_is_ipv6addr(host))
                LOGI("tcp server listening at [%s]:%s", host, port);
            else
                LOGI("tcp server listening at %s:%s", host ? host : "0.0.0.0", port);

            // Bind to port
            int listenfd;
            listenfd = create_and_bind(host, port, mptcp);
            if (listenfd == -1) {
                continue;
            }
            if (listen(listenfd, SSMAXCONN) == -1) {
                ERROR("listen()");
                continue;
            }
            setfastopen(listenfd);
            setnonblocking(listenfd);
            listen_ctx_t *listen_ctx = &listen_ctx_list[i];

            // Setup proxy context
            listen_ctx->timeout = atoi(timeout);
            listen_ctx->fd      = listenfd;
            listen_ctx->iface   = iface;
            listen_ctx->loop    = loop;

            ev_io_init(&listen_ctx->io, accept_cb, listenfd, EV_READ);
            ev_io_start(loop, &listen_ctx->io);

            num_listen_ctx++;

            if (plugin != NULL)
                break;
        }

        if (num_listen_ctx == 0) {
            FATAL("failed to listen on any address");
        }
    }

    if (mode != TCP_ONLY) {
        int num_listen_ctx = 0;
        for (int i = 0; i < server_num; i++) {
            const char *host = server_addr[i].host;
            const char *port = server_addr[i].port ? server_addr[i].port : server_port;
            if (plugin != NULL) {
                port = plugin_port;
            }
            if (host && ss_is_ipv6addr(host))
                LOGI("udp server listening at [%s]:%s", host, port);
            else
                LOGI("udp server listening at %s:%s", host ? host : "0.0.0.0", port);
            // Setup UDP
            int err = init_udprelay(host, port, mtu, crypto, atoi(timeout), iface);
            if (err == -1)
                continue;
            num_listen_ctx++;
        }

        if (num_listen_ctx == 0) {
            FATAL("failed to listen on any address");
        }
    }

#ifndef __MINGW32__
    if (manager_addr != NULL) {
        ev_timer_init(&stat_update_watcher, stat_update_cb, UPDATE_INTERVAL, UPDATE_INTERVAL);
        ev_timer_start(EV_DEFAULT, &stat_update_watcher);
    }
#endif

#ifndef __MINGW32__
    // setuid
    if (user != NULL && !run_as(user)) {
        FATAL("failed to switch user");
    }

    if (geteuid() == 0) {
        LOGI("running from root user");
    }
#endif

    // Init connections
    cork_dllist_init(&connections);

    // start ev loop
    ev_run(loop, 0);

    if (verbose) {
        LOGI("closed gracefully");
    }

#ifndef __MINGW32__
    if (manager_addr != NULL) {
        ev_timer_stop(EV_DEFAULT, &stat_update_watcher);
    }
#endif

    if (plugin != NULL) {
        stop_plugin();
    }

    // Clean up

    resolv_shutdown(loop);

    for (int i = 0; i < server_num; i++) {
        listen_ctx_t *listen_ctx = &listen_ctx_list[i];
        if (mode != UDP_ONLY) {
            ev_io_stop(loop, &listen_ctx->io);
            close(listen_ctx->fd);
        }
        if (plugin != NULL)
            break;
    }

    if (mode != UDP_ONLY) {
        free_connections(loop);
    }

    if (mode != TCP_ONLY) {
        free_udprelay();
    }

#ifdef __MINGW32__
    if (plugin_watcher.valid) {
        closesocket(plugin_watcher.fd);
    }

    winsock_cleanup();
#endif

    return ret_val;
}

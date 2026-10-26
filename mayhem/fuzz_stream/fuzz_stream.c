/*
 * Fuzz target for libuv's I/O stack: streams (pipes, TCP) and UDP, driven in-process over local
 * transports so no external network is needed. The input selects a transport, then is a script
 * of operations (write, try_write, read start/stop, shutdown, close, option queries, event-loop
 * turns) applied to the two connected endpoints:
 *   0 socketpair pipes        1 IPC socketpair (descriptor passing via uv_write2)
 *   2 abstract-name pipe server (uv_pipe_bind2 / uv_listen / uv_pipe_connect2 / uv_accept)
 *   3 loopback TCP            4 loopback UDP
 * Only valid API use is generated (nothing is touched after uv_close), so a crash is a libuv defect.
 */
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "uv.h"
#include "reader.h"

enum { M_PAIR, M_IPC, M_SERVER, M_TCP, M_UDP, M_COUNT };

typedef union {
    uv_handle_t h;
    uv_stream_t s;
    uv_pipe_t pipe;
    uv_tcp_t tcp;
    uv_udp_t udp;
} any_t;

typedef struct {
    any_t u;
    int init;
    int closing;
    int tcp;
} ep_t;

#define NEXTRA 4

static uv_loop_t loop;
static ep_t ep[2];
static ep_t aux[2];     /* IPC mode: pair whose handles get sent over the stream */
static ep_t extra[NEXTRA];  /* IPC mode: handles received from the peer */
static int nextra;
static int mode;
static size_t alloc_size;
static struct sockaddr_in udp_addr[2];

static int connected, accepted, connect_failed;

static void ep_register(ep_t *e, int tcp);

static void alloc_cb(uv_handle_t *h, size_t suggested, uv_buf_t *buf) {
    (void)h;
    size_t n = alloc_size ? alloc_size : suggested;
    if (n > suggested && suggested)
        n = suggested;
    buf->base = (char *)malloc(n ? n : 1);
    buf->len = buf->base ? n : 0;
}

static void read_cb(uv_stream_t *s, ssize_t nread, const uv_buf_t *buf) {
    if (buf && buf->base)
        free(buf->base);
    if (nread < 0) {
        uv_read_stop(s);
        return;
    }
    if (uv_handle_get_type((uv_handle_t *)s) == UV_NAMED_PIPE &&
        uv_pipe_pending_count((uv_pipe_t *)s) > 0 && nextra < NEXTRA) {
        if (uv_pipe_pending_type((uv_pipe_t *)s) == UV_NAMED_PIPE) {
            ep_t *e = &extra[nextra];
            if (uv_pipe_init(&loop, &e->u.pipe, 0) == 0) {
                ep_register(e, 0);
                nextra++;
                if (uv_accept(s, &e->u.s) == 0)
                    uv_read_start(&e->u.s, alloc_cb, read_cb);
            }
        }
    }
}

static void recv_cb(uv_udp_t *h, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr,
                    unsigned flags) {
    (void)h; (void)nread; (void)addr; (void)flags;
    if (buf && buf->base)
        free(buf->base);
}

typedef struct {
    union { uv_write_t w; uv_udp_send_t u; uv_shutdown_t sd; } req;
    uv_buf_t bufs[3];
    char data[1];
} wreq_t;

static void write_done(uv_write_t *r, int status) { (void)status; free(r); }
static void send_done(uv_udp_send_t *r, int status) { (void)status; free(r); }
static void shutdown_done(uv_shutdown_t *r, int status) { (void)status; free(r); }

static void close_cb(uv_handle_t *h) {
    ((ep_t *)h->data)->closing = 2;
}

static int ep_live(const ep_t *e) { return e->init && e->closing == 0; }

static void ep_close(ep_t *e) {
    if (!ep_live(e))
        return;
    e->closing = 1;
    if (e->tcp && uv_tcp_close_reset(&e->u.tcp, close_cb) == 0)
        return;
    uv_close(&e->u.h, close_cb);
}

static void ep_register(ep_t *e, int tcp) {
    e->init = 1;
    e->closing = 0;
    e->tcp = tcp;
    e->u.h.data = e;
}

static void connect_cb(uv_connect_t *r, int status) {
    free(r);
    if (status == 0)
        connected = 1;
    else
        connect_failed = 1;
}

static void connection_cb(uv_stream_t *server, int status) {
    if (status != 0 || accepted)
        return;
    if (mode == M_SERVER)
        uv_pipe_init(&loop, &ep[1].u.pipe, 0);
    else
        uv_tcp_init(&loop, &ep[1].u.tcp);
    ep_register(&ep[1], mode == M_TCP);
    if (uv_accept(server, &ep[1].u.s) == 0)
        accepted = 1;
    else {
        uv_close(&ep[1].u.h, close_cb);
        ep[1].closing = 1;
        connect_failed = 1;
    }
}

static int open_socketpair(int type, int *fds) {
    return socketpair(AF_UNIX, type, 0, fds);
}

static int setup_pair(int ipc) {
    int fds[2];
    if (open_socketpair(SOCK_STREAM, fds) != 0)
        return -1;
    for (int i = 0; i < 2; i++) {
        uv_pipe_init(&loop, &ep[i].u.pipe, ipc);
        ep_register(&ep[i], 0);
        if (uv_pipe_open(&ep[i].u.pipe, fds[i]) != 0) {
            close(fds[i]);
            uv_close(&ep[i].u.h, close_cb);
            ep[i].closing = 1;
        }
    }
    if (ipc) {
        int afds[2];
        if (open_socketpair(SOCK_STREAM, afds) == 0) {
            for (int i = 0; i < 2; i++) {
                uv_pipe_init(&loop, &aux[i].u.pipe, 0);
                ep_register(&aux[i], 0);
                if (uv_pipe_open(&aux[i].u.pipe, afds[i]) != 0) {
                    close(afds[i]);
                    uv_close(&aux[i].u.h, close_cb);
                    aux[i].closing = 1;
                }
            }
        }
    }
    return 0;
}

static int run_until(volatile int *a, volatile int *b) {
    for (int i = 0; i < 50 && !(*a && *b) && !connect_failed; i++)
        uv_run(&loop, UV_RUN_ONCE);
    return *a && *b;
}

static int setup_server(rd_t *r, int flags_byte) {
    char name[64];
    size_t n = rd_u8(r) % 40, got;
    const uint8_t *src = rd_bytes(r, n, &got);
    name[0] = '\0';
    memcpy(name + 1, "uvfz", 4);
    memcpy(name + 5, src, got);
    size_t namelen = 5 + got;
    unsigned flags = (flags_byte & 1) ? UV_PIPE_NO_TRUNCATE : 0;

    uv_pipe_t *srv = (uv_pipe_t *)calloc(1, sizeof(any_t));
    if (!srv)
        return -1;
    uv_pipe_init(&loop, srv, 0);
    int ok = uv_pipe_bind2(srv, name, namelen, flags) == 0 && uv_listen((uv_stream_t *)srv, 1 + (flags_byte >> 1) % 4, connection_cb) == 0;
    if (ok) {
        char buf[128];
        size_t sz = sizeof(buf);
        uv_pipe_getsockname(srv, buf, &sz);
        uv_pipe_chmod(srv, UV_READABLE | UV_WRITABLE);
        uv_pipe_init(&loop, &ep[0].u.pipe, 0);
        ep_register(&ep[0], 0);
        uv_connect_t *req = (uv_connect_t *)calloc(1, sizeof(*req));
        if (req && uv_pipe_connect2(req, &ep[0].u.pipe, name, namelen, flags, connect_cb) != 0) {
            free(req);
            connect_failed = 1;
        }
        ok = run_until(&connected, &accepted);
        if (ok) {
            sz = sizeof(buf);
            uv_pipe_getpeername(&ep[0].u.pipe, buf, &sz);
        }
    }
    uv_close((uv_handle_t *)srv, (uv_close_cb)free);
    return ok ? 0 : -1;
}

static int setup_tcp(int flags_byte) {
    uv_tcp_t *srv = (uv_tcp_t *)calloc(1, sizeof(any_t));
    if (!srv)
        return -1;
    struct sockaddr_in addr, bound;
    int len = sizeof(bound), ok = 0;
    uv_ip4_addr("127.0.0.1", 0, &addr);
    uv_tcp_init(&loop, srv);
    if (uv_tcp_bind(srv, (const struct sockaddr *)&addr, 0) == 0 &&
        uv_tcp_getsockname(srv, (struct sockaddr *)&bound, &len) == 0 &&
        uv_listen((uv_stream_t *)srv, 1 + flags_byte % 4, connection_cb) == 0) {
        uv_tcp_init(&loop, &ep[0].u.tcp);
        ep_register(&ep[0], 1);
        uv_connect_t *req = (uv_connect_t *)calloc(1, sizeof(*req));
        if (req && uv_tcp_connect(req, &ep[0].u.tcp, (const struct sockaddr *)&bound, connect_cb) != 0) {
            free(req);
            connect_failed = 1;
        }
        ok = run_until(&connected, &accepted);
    }
    uv_close((uv_handle_t *)srv, (uv_close_cb)free);
    return ok ? 0 : -1;
}

static int setup_udp(void) {
    struct sockaddr_in addr;
    uv_ip4_addr("127.0.0.1", 0, &addr);
    for (int i = 0; i < 2; i++) {
        int len = sizeof(udp_addr[i]);
        if (uv_udp_init(&loop, &ep[i].u.udp) != 0)
            return -1;
        ep_register(&ep[i], 0);
        if (uv_udp_bind(&ep[i].u.udp, (const struct sockaddr *)&addr, 0) != 0 ||
            uv_udp_getsockname(&ep[i].u.udp, (struct sockaddr *)&udp_addr[i], &len) != 0)
            return -1;
    }
    return 0;
}

static void do_write(ep_t *e, int peer, rd_t *r, uint8_t sel) {
    size_t got;
    uint8_t len = rd_u8(r);
    const uint8_t *src = rd_bytes(r, len, &got);
    unsigned reps = 1 + (sel >> 2) % 32;
    unsigned nb = 1 + (sel >> 7) % 2 + (sel & 1);
    size_t total = got * reps;
    wreq_t *w = (wreq_t *)calloc(1, sizeof(*w) + total + 1);
    if (!w)
        return;
    for (unsigned i = 0; i < reps && got; i++)
        memcpy(w->data + i * got, src, got);
    size_t cut = total / nb, off = 0;
    for (unsigned i = 0; i < nb; i++) {
        size_t l = (i == nb - 1) ? total - off : cut;
        w->bufs[i] = uv_buf_init(w->data + off, (unsigned)l);
        off += l;
    }
    if (mode == M_UDP) {
        const struct sockaddr *to = (sel & 2) ? NULL : (const struct sockaddr *)&udp_addr[peer];
        if (sel & 0x40) {
            (void)uv_udp_try_send(&e->u.udp, w->bufs, nb, to);
        } else if (uv_udp_send(&w->req.u, &e->u.udp, w->bufs, nb, to, send_done) == 0) {
            return;
        }
    } else if (mode == M_IPC && (sel & 0x20) && total > 0 && ep_live(&aux[sel & 1])) {
        if (uv_write2(&w->req.w, &e->u.s, w->bufs, nb, &aux[sel & 1].u.s, write_done) == 0)
            return;
    } else if (sel & 0x40) {
        (void)uv_try_write(&e->u.s, w->bufs, nb);
    } else if (uv_write(&w->req.w, &e->u.s, w->bufs, nb, write_done) == 0) {
        return;
    }
    free(w);
}

static void do_query(ep_t *e, uint8_t a, uint8_t b) {
    if (mode == M_UDP) {
        switch (a % 8) {
        case 0: uv_udp_set_ttl(&e->u.udp, b); break;
        case 1: uv_udp_set_broadcast(&e->u.udp, b & 1); break;
        case 2: uv_udp_set_multicast_loop(&e->u.udp, b & 1); break;
        case 3: uv_udp_set_multicast_ttl(&e->u.udp, b); break;
        case 4: { int v = b; uv_send_buffer_size(&e->u.h, &v); break; }
        case 5: { int v = b; uv_recv_buffer_size(&e->u.h, &v); break; }
        case 6: (void)uv_udp_get_send_queue_size(&e->u.udp); (void)uv_udp_get_send_queue_count(&e->u.udp); break;
        case 7:
            if (b & 1)
                uv_udp_connect(&e->u.udp, (const struct sockaddr *)&udp_addr[(e - ep) ^ 1]);
            else
                uv_udp_connect(&e->u.udp, NULL);
            break;
        }
        return;
    }
    switch (a % 8) {
    case 0: (void)uv_stream_get_write_queue_size(&e->u.s); break;
    case 1: (void)uv_is_readable(&e->u.s); (void)uv_is_writable(&e->u.s); break;
    case 2: { int v = b; uv_send_buffer_size(&e->u.h, &v); break; }
    case 3: { int v = b; uv_recv_buffer_size(&e->u.h, &v); break; }
    case 4: {
        char buf[128];
        size_t sz = sizeof(buf);
        if (mode == M_TCP) {
            struct sockaddr_storage ss;
            int l = sizeof(ss);
            uv_tcp_getsockname(&e->u.tcp, (struct sockaddr *)&ss, &l);
            l = sizeof(ss);
            uv_tcp_getpeername(&e->u.tcp, (struct sockaddr *)&ss, &l);
        } else {
            uv_pipe_getsockname(&e->u.pipe, buf, &sz);
        }
        break;
    }
    case 5:
        if (e->tcp) {
            uv_tcp_nodelay(&e->u.tcp, b & 1);
            uv_tcp_keepalive(&e->u.tcp, b & 1, b >> 1);
        }
        break;
    case 6: { uv_os_fd_t fd; uv_fileno(&e->u.h, &fd); break; }
    case 7:
        if (e->tcp)
            uv_tcp_keepalive_ex(&e->u.tcp, b & 1, 1 + (b >> 1), 1 + (b >> 3), 1 + (b >> 5));
        break;
    }
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    signal(SIGPIPE, SIG_IGN);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2)
        return -1;
    rd_t r = {data, size};
    mode = rd_u8(&r) % M_COUNT;
    uint8_t cfg = rd_u8(&r);
    memset(ep, 0, sizeof(ep));
    memset(aux, 0, sizeof(aux));
    memset(extra, 0, sizeof(extra));
    nextra = 0;
    alloc_size = 0;
    connected = accepted = connect_failed = 0;

    if (uv_loop_init(&loop) != 0)
        return 0;

    int rc;
    switch (mode) {
    case M_PAIR: rc = setup_pair(0); break;
    case M_IPC: rc = setup_pair(1); break;
    case M_SERVER: rc = setup_server(&r, cfg); break;
    case M_TCP: rc = setup_tcp(cfg); break;
    default: rc = setup_udp(); break;
    }

    if (rc == 0) {
        int budget = 120;
        while (rd_more(&r) && budget-- > 0) {
            uint8_t op = rd_u8(&r);
            ep_t *e = &ep[op & 1];
            int peer = (op & 1) ^ 1;
            if (!ep_live(e)) {
                uv_run(&loop, UV_RUN_NOWAIT);
                continue;
            }
            switch ((op >> 1) % 10) {
            case 0: case 1: do_write(e, peer, &r, rd_u8(&r)); break;
            case 2:
                if (mode == M_UDP)
                    uv_udp_recv_start(&e->u.udp, alloc_cb, recv_cb);
                else
                    uv_read_start(&e->u.s, alloc_cb, read_cb);
                break;
            case 3:
                if (mode == M_UDP)
                    uv_udp_recv_stop(&e->u.udp);
                else
                    uv_read_stop(&e->u.s);
                break;
            case 4:
                if (mode != M_UDP) {
                    uv_shutdown_t *sd = (uv_shutdown_t *)calloc(1, sizeof(*sd));
                    if (sd && uv_shutdown(sd, &e->u.s, shutdown_done) != 0)
                        free(sd);
                }
                break;
            case 5: ep_close(e); break;
            case 6: case 7: uv_run(&loop, UV_RUN_NOWAIT); break;
            case 8: do_query(e, rd_u8(&r), rd_u8(&r)); break;
            case 9: alloc_size = rd_u8(&r) % 80; break;
            }
        }
    }

    ep_close(&ep[0]);
    ep_close(&ep[1]);
    ep_close(&aux[0]);
    ep_close(&aux[1]);
    for (int i = 0; i < nextra; i++)
        ep_close(&extra[i]);
    for (int i = 0; i < 3; i++) {
        uv_run(&loop, UV_RUN_DEFAULT);
        if (uv_loop_close(&loop) == 0)
            break;
    }
    return 0;
}

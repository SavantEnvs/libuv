/*
 * Fuzz target for libuv's event loop core: the timer heap, idle/prepare/check watchers, async
 * wakeups, signal handles, the threadpool work queue, handle ref/close bookkeeping and loop
 * metrics. The input is a script of operations; callbacks also read their next action from the
 * same script, so handles are stopped, closed, restarted and created from inside callbacks
 * (re-entrancy into the loop's intrusive queues and the timer heap).
 *
 * Only valid API use is generated (no calls on a handle after uv_close), so any crash is a
 * libuv defect. Signal handles use SIGWINCH/SIGURG, whose default action is "ignore".
 */
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "uv.h"
#include "reader.h"

#define NSLOT 10

enum { K_TIMER, K_IDLE, K_PREPARE, K_CHECK, K_ASYNC, K_SIGNAL, K_COUNT };

typedef union {
    uv_handle_t h;
    uv_timer_t timer;
    uv_idle_t idle;
    uv_prepare_t prepare;
    uv_check_t check;
    uv_async_t async;
    uv_signal_t signal;
} any_handle_t;

typedef struct {
    any_handle_t *h;
    int kind;
    int closing;
} slot_t;

static uv_loop_t loop;
static slot_t slots[NSLOT];
static rd_t *script;
static int finishing;
static unsigned long events;

static void on_event(uv_handle_t *h);

static void timer_cb(uv_timer_t *h) { on_event((uv_handle_t *)h); }
static void idle_cb(uv_idle_t *h) { on_event((uv_handle_t *)h); }
static void prepare_cb(uv_prepare_t *h) { on_event((uv_handle_t *)h); }
static void check_cb(uv_check_t *h) { on_event((uv_handle_t *)h); }
static void async_cb(uv_async_t *h) { on_event((uv_handle_t *)h); }
static void signal_cb(uv_signal_t *h, int signum) { (void)signum; on_event((uv_handle_t *)h); }

static void close_cb(uv_handle_t *h) {
    slot_t *s = (slot_t *)h->data;
    free(s->h);
    s->h = NULL;
    s->closing = 0;
}

static void slot_close(slot_t *s) {
    if (s->h && !s->closing) {
        s->closing = 1;
        uv_close(&s->h->h, close_cb);
    }
}

static int slot_live(const slot_t *s) { return s->h && !s->closing; }

static void slot_start(slot_t *s, uint8_t a, uint8_t b) {
    if (!slot_live(s))
        return;
    switch (s->kind) {
    case K_TIMER: uv_timer_start(&s->h->timer, timer_cb, a % 4, b % 3); break;
    case K_IDLE: uv_idle_start(&s->h->idle, idle_cb); break;
    case K_PREPARE: uv_prepare_start(&s->h->prepare, prepare_cb); break;
    case K_CHECK: uv_check_start(&s->h->check, check_cb); break;
    case K_ASYNC: uv_async_send(&s->h->async); break;
    case K_SIGNAL:
        if (b & 1)
            uv_signal_start_oneshot(&s->h->signal, signal_cb, (a & 1) ? SIGWINCH : SIGURG);
        else
            uv_signal_start(&s->h->signal, signal_cb, (a & 1) ? SIGWINCH : SIGURG);
        break;
    }
}

static void slot_stop(slot_t *s) {
    if (!slot_live(s))
        return;
    switch (s->kind) {
    case K_TIMER: uv_timer_stop(&s->h->timer); break;
    case K_IDLE: uv_idle_stop(&s->h->idle); break;
    case K_PREPARE: uv_prepare_stop(&s->h->prepare); break;
    case K_CHECK: uv_check_stop(&s->h->check); break;
    case K_SIGNAL: uv_signal_stop(&s->h->signal); break;
    default: break;
    }
}

static void slot_init(slot_t *s, int kind) {
    if (s->h)
        return;
    any_handle_t *h = (any_handle_t *)calloc(1, sizeof(*h));
    if (!h)
        return;
    int r = -1;
    switch (kind) {
    case K_TIMER: r = uv_timer_init(&loop, &h->timer); break;
    case K_IDLE: r = uv_idle_init(&loop, &h->idle); break;
    case K_PREPARE: r = uv_prepare_init(&loop, &h->prepare); break;
    case K_CHECK: r = uv_check_init(&loop, &h->check); break;
    case K_ASYNC: r = uv_async_init(&loop, &h->async, async_cb); break;
    case K_SIGNAL: r = uv_signal_init(&loop, &h->signal); break;
    }
    if (r != 0) {
        free(h);
        return;
    }
    h->h.data = s;
    s->h = h;
    s->kind = kind;
    s->closing = 0;
    if (kind != K_TIMER && kind != K_IDLE)
        uv_unref(&h->h);
}

/* Only timers, idle handles and work requests make uv_run(ONCE) return by themselves. */
static void unref_nonwaking_handles(void) {
    for (int i = 0; i < NSLOT; i++)
        if (slot_live(&slots[i]) && slots[i].kind != K_TIMER && slots[i].kind != K_IDLE)
            uv_unref(&slots[i].h->h);
}

static void on_event(uv_handle_t *self) {
    slot_t *me = (slot_t *)self->data;
    if (finishing || !rd_more(script))
        return;
    uint8_t act = rd_u8(script);
    slot_t *other = &slots[rd_u8(script) % NSLOT];
    switch (act % 10) {
    case 0: break;
    case 1: slot_stop(me); break;
    case 2: slot_close(me); break;
    case 3: slot_stop(other); break;
    case 4: slot_close(other); break;
    case 5: slot_start(other, rd_u8(script), rd_u8(script)); break;
    case 6: uv_stop(&loop); break;
    case 7: if (slot_live(other) && other->kind == K_ASYNC) uv_async_send(&other->h->async); break;
    case 8: slot_init(other, rd_u8(script) % K_COUNT); slot_start(other, rd_u8(script), 0); break;
    case 9:
        if (slot_live(me) && me->kind == K_TIMER) {
            uv_timer_set_repeat(&me->h->timer, rd_u8(script) % 3);
            uv_timer_again(&me->h->timer);
        }
        break;
    }
}

static void work_cb(uv_work_t *req) { (void)req; }
static void after_work_cb(uv_work_t *req, int status) { (void)status; free(req); }

static void walk_cb(uv_handle_t *h, void *arg) {
    unsigned *n = (unsigned *)arg;
    *n += (unsigned)uv_is_active(h) + (unsigned)uv_has_ref(h) + (unsigned)uv_is_closing(h);
    (void)uv_handle_type_name(uv_handle_get_type(h));
}

static void do_misc(uint8_t a) {
    switch (a % 6) {
    case 0: uv_update_time(&loop); (void)uv_now(&loop); break;
    case 1: (void)uv_backend_timeout(&loop); (void)uv_loop_alive(&loop); break;
    case 2: { unsigned n = 0; uv_walk(&loop, walk_cb, &n); break; }
    case 3: { uv_metrics_t m; uv_metrics_info(&loop, &m); (void)uv_metrics_idle_time(&loop); break; }
    case 4: uv_kill(getpid(), SIGWINCH); break;
    case 5: (void)uv_backend_fd(&loop); break;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2)
        return -1;
    rd_t r = {data, size};
    script = &r;
    finishing = 0;
    events = 0;
    memset(slots, 0, sizeof(slots));

    if (uv_loop_init(&loop) != 0)
        return 0;
    uint8_t cfg = rd_u8(&r);
    if (cfg & 1)
        uv_loop_configure(&loop, UV_METRICS_IDLE_TIME);
    if (cfg & 2)
        uv_loop_configure(&loop, UV_LOOP_BLOCK_SIGNAL, SIGPROF);

    int budget = 200;
    while (rd_more(&r) && budget-- > 0) {
        uint8_t op = rd_u8(&r);
        slot_t *s = &slots[rd_u8(&r) % NSLOT];
        switch (op % 14) {
        case 0: case 1: slot_init(s, rd_u8(&r) % K_COUNT); break;
        case 2: case 3: { uint8_t a = rd_u8(&r), b = rd_u8(&r); slot_start(s, a, b); break; }
        case 4: slot_stop(s); break;
        case 5: slot_close(s); break;
        case 6:
            if (slot_live(s)) {
                uint8_t a = rd_u8(&r);
                if (s->kind == K_TIMER) {
                    uv_timer_set_repeat(&s->h->timer, a % 3);
                    (void)uv_timer_get_repeat(&s->h->timer);
                    (void)uv_timer_get_due_in(&s->h->timer);
                    uv_timer_again(&s->h->timer);
                }
            }
            break;
        case 7:
            if (slot_live(s)) {
                uint8_t a = rd_u8(&r);
                if (a & 1)
                    uv_ref(&s->h->h);
                else
                    uv_unref(&s->h->h);
                (void)uv_has_ref(&s->h->h);
                (void)uv_is_active(&s->h->h);
                (void)uv_is_closing(&s->h->h);
            }
            break;
        case 8: case 9: uv_run(&loop, UV_RUN_NOWAIT); break;
        case 10:
            unref_nonwaking_handles();
            uv_run(&loop, UV_RUN_ONCE);
            break;
        case 11: {
            uv_work_t *w = (uv_work_t *)calloc(1, sizeof(*w));
            if (w) {
                uint8_t a = rd_u8(&r);
                if (uv_queue_work(&loop, w, work_cb, after_work_cb) != 0)
                    free(w);
                else if (a & 1)
                    uv_cancel((uv_req_t *)w);
            }
            break;
        }
        case 12: do_misc(rd_u8(&r)); break;
        case 13: uv_stop(&loop); break;
        }
    }

    /* Tear down: stop script-driven callbacks, close everything, drain, close the loop. */
    finishing = 1;
    for (int i = 0; i < NSLOT; i++)
        slot_close(&slots[i]);
    /* A pending uv_stop() makes the first DEFAULT run return early; a second run drains the rest. */
    for (int i = 0; i < 3; i++) {
        uv_run(&loop, UV_RUN_DEFAULT);
        if (uv_loop_close(&loop) == 0)
            break;
    }
    script = NULL;
    return 0;
}

/* Tiny byte-stream reader shared by the interpreter-style harnesses (input = a script of ops). */
#ifndef MAYHEM_READER_H
#define MAYHEM_READER_H
#include <stddef.h>
#include <stdint.h>

typedef struct {
    const uint8_t *p;
    size_t n;
} rd_t;

static inline int rd_more(const rd_t *r) { return r->n > 0; }

static inline uint8_t rd_u8(rd_t *r) {
    if (r->n == 0)
        return 0;
    r->n--;
    return *r->p++;
}

static inline uint16_t rd_u16(rd_t *r) {
    uint16_t hi = rd_u8(r);
    return (uint16_t)(hi << 8 | rd_u8(r));
}

/* Up to `want` bytes (fewer at end of input); *got reports how many. */
static inline const uint8_t *rd_bytes(rd_t *r, size_t want, size_t *got) {
    const uint8_t *s = r->p;
    if (want > r->n)
        want = r->n;
    r->p += want;
    r->n -= want;
    *got = want;
    return s;
}
#endif

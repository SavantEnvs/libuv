/*
 * Fuzz target for libuv's WTF-8 <-> UTF-16 conversion (the Windows path-encoding helpers,
 * compiled on every platform). Byte input is exercised both as a WTF-8 string and as raw
 * UTF-16 code units.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "uv.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0)
        return 0;

    /* 1. Treat the input as a NUL-terminated WTF-8 string and convert to UTF-16. */
    char *str = (char *)malloc(size + 1);
    if (!str)
        return 0;
    memcpy(str, data, size);
    str[size] = 0;

    ssize_t wlen = uv_wtf8_length_as_utf16(str);
    if (wlen < 0) {
        free(str);
        return -1;
    }

    uint16_t *wide = (uint16_t *)malloc((size_t)wlen * sizeof(uint16_t));
    if (!wide) {
        free(str);
        return 0;
    }
    uv_wtf8_to_utf16(str, wide, (size_t)wlen);

    /* 2. Round-trip back to WTF-8 (the trailing NUL is not counted). */
    char *back = NULL;
    size_t back_len = 0;
    if (uv_utf16_to_wtf8(wide, wlen - 1, &back, &back_len) == 0)
        free(back);
    free(wide);
    free(str);

    /* 3. Treat the raw bytes as UTF-16 code units (arbitrary surrogates). */
    size_t units = size / 2;
    if (units > 0) {
        uint16_t *raw = (uint16_t *)malloc(units * sizeof(uint16_t));
        if (!raw)
            return 0;
        memcpy(raw, data, units * sizeof(uint16_t));
        size_t need = uv_utf16_length_as_wtf8(raw, (ssize_t)units);
        char *out = (char *)malloc(need + 1);
        if (out) {
            size_t out_len = need;
            if (uv_utf16_to_wtf8(raw, (ssize_t)units, &out, &out_len) != 0)
                abort();
            free(out);
        }
        free(raw);
    }

    return 0;
}

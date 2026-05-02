/*
 * Fuzz target for libuv IDNA/hostname parsing and IP address parsing.
 * Exercises uv__idna_toascii (internal), uv__utf8_decode1 (internal),
 * uv_ip4_addr, uv_ip6_addr, and uv_inet_pton (public APIs).
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Pull in internal headers for IDNA/UTF-8 decode */
#include "../src/idna.h"

/* Pull in public API */
#include "../include/uv.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0)
        return 0;

    /* Null-terminate a copy for functions expecting C strings */
    char *input = (char *)malloc(size + 1);
    if (!input)
        return 0;
    memcpy(input, data, size);
    input[size] = 0;

    /* 1. IDNA toascii: encode hostname to ASCII/Punycode */
    {
        char out[1024];
        uv__idna_toascii(input, input + size, out, out + sizeof(out));
    }

    /* 2. UTF-8 decode: walk through input decoding codepoints */
    {
        const char *p = input;
        const char *pe = input + size;
        while (p < pe)
            uv__utf8_decode1(&p, pe);
    }

    /* 3. uv_ip4_addr: parse as IPv4 address:port string */
    {
        struct sockaddr_in addr4;
        uv_ip4_addr(input, 0, &addr4);
    }

    /* 4. uv_ip6_addr: parse as IPv6 address:port string */
    {
        struct sockaddr_in6 addr6;
        uv_ip6_addr(input, 0, &addr6);
    }

    /* 5. uv_inet_pton IPv4 */
    {
        unsigned char buf[16];
        uv_inet_pton(AF_INET, input, buf);
    }

    /* 6. uv_inet_pton IPv6 */
    {
        unsigned char buf[16];
        uv_inet_pton(AF_INET6, input, buf);
    }

    free(input);
    return 0;
}

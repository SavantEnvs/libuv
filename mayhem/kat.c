/* Known-answer probe: fixed input -> asserted output, through the clean (unsanitized) libuv. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "uv.h"
#include "src/idna.h"

static int failures;

#define CHECK(name, cond) do { \
    int ok_ = !!(cond); \
    printf("%s %s\n", ok_ ? "KAT_OK" : "KAT_FAIL", name); \
    if (!ok_) failures++; \
} while (0)

int main(void) {
    struct sockaddr_in a4;
    struct sockaddr_in6 a6;
    char name[64];
    char out[128];
    ssize_t n;

    CHECK("ip4_addr_ok", uv_ip4_addr("192.0.2.33", 8080, &a4) == 0);
    CHECK("ip4_port", ntohs(a4.sin_port) == 8080);
    CHECK("ip4_name", uv_ip4_name(&a4, name, sizeof(name)) == 0 && strcmp(name, "192.0.2.33") == 0);
    CHECK("ip4_reject", uv_ip4_addr("255.255.255.256", 1, &a4) == UV_EINVAL);

    CHECK("ip6_addr_ok", uv_ip6_addr("2001:db8::8a2e:370:7334", 443, &a6) == 0);
    CHECK("ip6_port", ntohs(a6.sin6_port) == 443);
    CHECK("ip6_name", uv_ip6_name(&a6, name, sizeof(name)) == 0 &&
                      strcmp(name, "2001:db8::8a2e:370:7334") == 0);
    CHECK("ip6_reject", uv_ip6_addr("not-an-address", 1, &a6) == UV_EINVAL);

    {
        static const char s[] = "b\xc3\xbc" "cher.example";
        n = uv__idna_toascii(s, s + sizeof(s) - 1, out, out + sizeof(out));
        CHECK("idna_bucher", n > 0 && strcmp(out, "xn--bcher-kva.example") == 0);
    }
    {
        static const char s[] = "plain.example";
        n = uv__idna_toascii(s, s + sizeof(s) - 1, out, out + sizeof(out));
        CHECK("idna_ascii_passthrough", n > 0 && strcmp(out, "plain.example") == 0);
    }

    {
        static const char s[] = "\xf0\x9f\x98\x80";  /* U+1F600 */
        uint16_t w[8];
        ssize_t wl = uv_wtf8_length_as_utf16(s);
        CHECK("wtf8_len", wl == 3);
        uv_wtf8_to_utf16(s, w, (size_t)wl);
        CHECK("wtf8_surrogates", w[0] == 0xD83D && w[1] == 0xDE00 && w[2] == 0);
        CHECK("utf16_len_as_wtf8", uv_utf16_length_as_wtf8(w, 2) == 4);
    }
    {
        static const char lone[] = "\xed\xa0\x80";
        CHECK("wtf8_lone_surrogate_len", uv_wtf8_length_as_utf16(lone) == 2);
    }

    CHECK("version_nonzero", uv_version() >= 0x010000);
    printf("KAT_DONE failures=%d\n", failures);
    return failures ? 1 : 0;
}

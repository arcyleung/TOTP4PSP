/*
 * Host-side TOTP regression tests for TOTP4PSP.
 *
 * Reproduces the pre-fix bug in calcToken (strlen + forced key length 21)
 * and verifies the fixed path against RFC 6238 / common authenticator keys.
 *
 * Build/run: make host-test
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "totp_core.h"
#include "base32/base32.h"
#include "hmac-sha1/src/hmac/hmac.h"

static int g_failed = 0;
static int g_passed = 0;

#define EXPECT_EQ_U32(label, got, want) do { \
    uint32_t _g = (got), _w = (want); \
    if (_g != _w) { \
        fprintf(stderr, "FAIL: %s: got %u (0x%x) want %u (0x%x)\n", \
                (label), _g, _g, _w, _w); \
        g_failed++; \
    } else { \
        printf("PASS: %s\n", (label)); \
        g_passed++; \
    } \
} while (0)

/*
 * Historical buggy key-length logic from main.c (pre-fix):
 *   - treated secret as a C string (strlen)
 *   - forced length to at least 21 for "short" secrets
 *   - always passed length = strlen+1 (or 21), reading past valid bytes
 *
 * HMAC-SHA1 zero-pads keys to the 64-byte block, so a trailing NUL alone
 * does not change the digest. The damage is:
 *   (1) secrets with embedded 0x00 are truncated by strlen
 *   (2) secrets with strlen < 20 use key length 21, incorporating heap garbage
 *       after the real secret into the HMAC key
 */
static uint32_t
buggy_calc_hotp(const uint8_t *secret, size_t alloc_cap, uint64_t counter)
{
    uint8_t text[8];
    int i;
    /* Intentionally wrong: C-string length of binary key */
    size_t slen = strlen((const char *)secret);
    size_t bufLen;
    uint8_t output[64];
    size_t outLen;
    int offset;
    uint32_t bin_code;

    (void)alloc_cap;

    if (slen < 20) {
        bufLen = 20 + 1; /* 21 — reads past real secret */
    } else {
        bufLen = slen + 1;
    }

    for (i = 7; i >= 0; i--) {
        text[i] = (uint8_t)(counter & 0xffu);
        counter >>= 8;
    }

    outLen = bufLen; /* historical: reused bufLen as in/out size wrongly-ish */
    /* Real historical call passed key length = bufLen (21 or strlen+1) */
    outLen = 20;
    hmac_sha1(secret, bufLen, text, 8, output, &outLen);

    offset = output[outLen - 1] & 0x0f;
    bin_code = ((uint32_t)(output[offset] & 0x7f) << 24)
             | ((uint32_t)(output[offset + 1] & 0xff) << 16)
             | ((uint32_t)(output[offset + 2] & 0xff) << 8)
             | ((uint32_t)(output[offset + 3] & 0xff));
    return bin_code;
}

static void
test_rfc6238_sha1(void)
{
    /* RFC 6238 Appendix B seed: ASCII "12345678901234567890" (20 bytes) */
    const uint8_t *sec = (const uint8_t *)"12345678901234567890";
    size_t len = 20;

    /* T=59 -> counter=1 -> 8-digit 94287082 */
    EXPECT_EQ_U32("RFC6238 T=59 8dig",
                  calc_totp(sec, len, 59 / 30, 8), 94287082u);
    EXPECT_EQ_U32("RFC6238 T=59 6dig",
                  calc_totp(sec, len, 59 / 30, 6), 287082u);

    EXPECT_EQ_U32("RFC6238 T=1111111109 8dig",
                  calc_totp(sec, len, 1111111109ull / 30, 8), 7081804u);
    EXPECT_EQ_U32("RFC6238 T=1111111111 8dig",
                  calc_totp(sec, len, 1111111111ull / 30, 8), 14050471u);
    EXPECT_EQ_U32("RFC6238 T=1234567890 8dig",
                  calc_totp(sec, len, 1234567890ull / 30, 8), 89005924u);
    EXPECT_EQ_U32("RFC6238 T=2000000000 8dig",
                  calc_totp(sec, len, 2000000000ull / 30, 8), 69279037u);
    EXPECT_EQ_U32("RFC6238 T=20000000000 8dig",
                  calc_totp(sec, len, 20000000000ull / 30, 8), 65353130u);
}

static void
test_base32_roundtrip_rfc_secret(void)
{
    const char *b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    char decoded[64];
    int n = base32_decode(b32, decoded, (int)sizeof(decoded));
    EXPECT_EQ_U32("base32 decode length", (uint32_t)n, 20u);
    if (n == 20 && memcmp(decoded, "12345678901234567890", 20) == 0) {
        printf("PASS: base32 decode contents\n");
        g_passed++;
    } else {
        fprintf(stderr, "FAIL: base32 decode contents\n");
        g_failed++;
    }
}

static void
test_short_secret_with_heap_garbage(void)
{
    /*
     * Common Google-Authenticator style key: 10 raw bytes (16 base32 chars).
     * Example secret JBSWY3DPEHPK3PXP -> "Hello!" + 0xDEADBEEF
     */
    const char *b32 = "JBSWY3DPEHPK3PXP";
    uint8_t buf[32];
    int n;
    uint32_t good, bad_zero_pad, bad_garbage;
    uint64_t counter = 1;

    memset(buf, 0, sizeof(buf));
    n = base32_decode(b32, (char *)buf, (int)sizeof(buf));
    EXPECT_EQ_U32("short key decode len", (uint32_t)n, 10u);

    good = mod_hotp(calc_hotp(buf, (size_t)n, counter), 6);

    /*
     * If the 11 bytes after the secret happen to be zero (lucky malloc, or
     * memset), buggy length-21 key still matches — HMAC key zero-pad identity.
     */
    {
        uint8_t lucky[32];
        memset(lucky, 0, sizeof(lucky));
        memcpy(lucky, buf, (size_t)n);
        bad_zero_pad = mod_hotp(buggy_calc_hotp(lucky, sizeof(lucky), counter), 6);
        EXPECT_EQ_U32("buggy+zero-pad accidentally OK for short key",
                      bad_zero_pad, good);
    }

    /*
     * Realistic PSP heap: non-zero junk after the decoded secret.
     * Pre-fix code forced key length 21 and mixed junk into HMAC key.
     */
    {
        uint8_t unlucky[32];
        size_t i;
        memset(unlucky, 0, sizeof(unlucky));
        memcpy(unlucky, buf, (size_t)n);
        /* Simulate uninitialized heap after the NUL written by base32_decode */
        for (i = (size_t)n + 1; i < 21; i++) {
            unlucky[i] = (uint8_t)(0xA5 ^ (i * 17));
        }
        bad_garbage = mod_hotp(buggy_calc_hotp(unlucky, sizeof(unlucky), counter), 6);
        if (bad_garbage == good) {
            fprintf(stderr,
                    "FAIL: expected short-key+garbage to differ from correct "
                    "(got both %06u)\n", good);
            g_failed++;
        } else {
            printf("PASS: short-key+garbage differs (good=%06u bad=%06u) "
                   "— reproduces pre-fix bug\n", good, bad_garbage);
            g_passed++;
        }

        /* Fixed path ignores bytes past secret_len */
        EXPECT_EQ_U32("fixed path ignores garbage after secret",
                      mod_hotp(calc_hotp(unlucky, (size_t)n, counter), 6), good);
    }
}

static void
test_embedded_nul_in_secret(void)
{
    /* Binary secret with an interior 0x00 — illegal as a C string. */
    uint8_t secret[] = {
        'a', 'b', 'c', 0x00, 'd', 'e', 'f', 'g',
        'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o'
    };
    size_t full_len = sizeof(secret);
    uint64_t counter = 42;
    uint32_t good = mod_hotp(calc_hotp(secret, full_len, counter), 6);
    uint32_t truncated = mod_hotp(calc_hotp(secret, 3, counter), 6); /* strlen stops at 3 */
    uint32_t buggy;

    if (good == truncated) {
        fprintf(stderr, "FAIL: embedded-NUL case needs full != strlen path\n");
        g_failed++;
    } else {
        printf("PASS: full key != strlen-truncated key (good=%06u trunc=%06u)\n",
               good, truncated);
        g_passed++;
    }

    buggy = mod_hotp(buggy_calc_hotp(secret, full_len, counter), 6);
    /* Buggy uses strlen=3 then forces length 21 with rest of buffer */
    if (buggy == good) {
        fprintf(stderr, "FAIL: buggy path should not match full embedded-NUL key\n");
        g_failed++;
    } else {
        printf("PASS: buggy path wrong for embedded NUL (good=%06u bad=%06u)\n",
               good, buggy);
        g_passed++;
    }

    EXPECT_EQ_U32("fixed embedded-NUL uses full length",
                  mod_hotp(calc_hotp(secret, full_len, counter), 6), good);
}

static void
test_rfc_secret_unaffected_by_plus_one_nul(void)
{
    /*
     * 20-byte ASCII seed: strlen==20, buggy used length 21 including trailing NUL.
     * HMAC block zero-pad makes that identical — explains why RFC sample "worked".
     */
    const uint8_t sec[21] = "12345678901234567890"; /* 20 chars + implicit need room */
    uint32_t a = mod_hotp(calc_hotp(sec, 20, 1), 6);
    uint32_t b = mod_hotp(calc_hotp(sec, 21, 1), 6); /* includes trailing NUL byte value 0 */
    EXPECT_EQ_U32("20-byte key same as 21 with trailing NUL (HMAC pad)", a, b);
    EXPECT_EQ_U32("RFC seed counter=1 is 287082", a, 287082u);
}

static void
test_hmac_sha1_rfc2202_case1(void)
{
    /* RFC 2202 test case 1 */
    uint8_t key[20];
    const uint8_t data[8] = "Hi There";
    uint8_t out[20];
    size_t t = 20;
    static const uint8_t expect[20] = {
        0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64,
        0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e,
        0xf1, 0x46, 0xbe, 0x00
    };
    int i;
    int ok = 1;

    memset(key, 0x0b, 20);
    hmac_sha1(key, 20, data, 8, out, &t);
    for (i = 0; i < 20; i++) {
        if (out[i] != expect[i]) {
            ok = 0;
            break;
        }
    }
    if (ok) {
        printf("PASS: HMAC-SHA1 RFC2202 case 1 (crypto lib OK)\n");
        g_passed++;
    } else {
        fprintf(stderr, "FAIL: HMAC-SHA1 RFC2202 case 1 — library broken\n");
        g_failed++;
    }
}

int
main(void)
{
    printf("=== TOTP4PSP host tests ===\n");
    test_hmac_sha1_rfc2202_case1();
    test_base32_roundtrip_rfc_secret();
    test_rfc6238_sha1();
    test_rfc_secret_unaffected_by_plus_one_nul();
    test_short_secret_with_heap_garbage();
    test_embedded_nul_in_secret();

    printf("\n%d passed, %d failed\n", g_passed, g_failed);
    return g_failed ? 1 : 0;
}

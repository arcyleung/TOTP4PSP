#include "totp_core.h"
#include "hmac-sha1/src/hmac/hmac.h"

uint32_t
mod_hotp(uint32_t bin_code, int digits)
{
    uint32_t power = 1;
    int i;
    for (i = 0; i < digits; i++) {
        power *= 10;
    }
    return bin_code % power;
}

uint32_t
calc_hotp(const uint8_t *secret, size_t secret_len, uint64_t counter)
{
    uint8_t text[8];
    int i;
    size_t out_len;
    uint8_t output[20];
    int offset;
    uint32_t bin_code;

    /* Counter as 8-byte big-endian (RFC 4226). */
    for (i = 7; i >= 0; i--) {
        text[i] = (uint8_t)(counter & 0xffu);
        counter >>= 8;
    }

    out_len = 20;
    hmac_sha1(secret, secret_len, text, 8, output, &out_len);

    offset = output[out_len - 1] & 0x0f;
    bin_code = ((uint32_t)(output[offset] & 0x7f) << 24)
             | ((uint32_t)(output[offset + 1] & 0xff) << 16)
             | ((uint32_t)(output[offset + 2] & 0xff) << 8)
             | ((uint32_t)(output[offset + 3] & 0xff));

    return bin_code;
}

uint32_t
calc_totp(const uint8_t *secret, size_t secret_len, uint64_t counter, int digits)
{
    return mod_hotp(calc_hotp(secret, secret_len, counter), digits);
}

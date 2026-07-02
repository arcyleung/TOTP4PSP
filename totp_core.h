#ifndef TOTP_CORE_H
#define TOTP_CORE_H

#include <stddef.h>
#include <stdint.h>

/* Supported authenticator digit widths (RFC 4226 / common apps). */
#define TOTP_DIGITS_MIN 6
#define TOTP_DIGITS_MAX 8

/* Clamp to [TOTP_DIGITS_MIN, TOTP_DIGITS_MAX]; invalid/zero -> 6. */
int totp_clamp_digits(int digits);

/* HOTP truncation modulo 10^digits (RFC 4226). Digits are clamped. */
uint32_t mod_hotp(uint32_t bin_code, int digits);

/*
 * HOTP binary code (dynamic truncation, before mod 10^d).
 * secret/secret_len are raw key bytes (after base32 decode), not a C string.
 */
uint32_t calc_hotp(const uint8_t *secret, size_t secret_len, uint64_t counter);

/* Full TOTP digit code: mod_hotp(calc_hotp(...), digits). */
uint32_t calc_totp(const uint8_t *secret, size_t secret_len, uint64_t counter,
                   int digits);

/*
 * Decode a base32 secret the same way the app must: binary length from
 * base32_decode return value (never strlen on decoded bytes).
 * Returns 0 on success and sets *out_len; -1 on decode/buffer error
 * (*out_len = 0).
 */
int totp_decode_secret_b32(const char *b32, uint8_t *out, int out_cap,
                           size_t *out_len);

#endif /* TOTP_CORE_H */

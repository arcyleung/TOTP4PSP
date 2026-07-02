#ifndef TOTP_CORE_H
#define TOTP_CORE_H

#include <stddef.h>
#include <stdint.h>

/* HOTP truncation modulo 10^digits (RFC 4226). */
uint32_t mod_hotp(uint32_t bin_code, int digits);

/*
 * HOTP binary code (dynamic truncation result, before mod 10^d).
 * secret/secret_len are the raw key bytes (after base32 decode), not a C string.
 * counter is the moving factor (T/X for TOTP).
 */
uint32_t calc_hotp(const uint8_t *secret, size_t secret_len, uint64_t counter);

/* Convenience: 6/7/8-digit OTP string value. */
uint32_t calc_totp(const uint8_t *secret, size_t secret_len, uint64_t counter,
                   int digits);

#endif /* TOTP_CORE_H */

# Epic: TOTP secret-length correctness (TOTP4PSP)

**Status:** walking-skeleton delivered (ITER-0000 complete); follow-ons optional

## Stories

### STORY-0001 — Binary secret length into HMAC
**Status:** done  
**Proof obligation:** HOTP/TOTP uses exact base32-decoded byte length `N`, never `strlen` or a forced minimum of 21.  
**Seam:** `totp_core.c:calc_hotp` + `main.c:readOTPFile` (`secret_len` from `base32_decode`).  
**Evidence:** `make host-test` (RFC6238, short-key+garbage, embedded-NUL cases).

### STORY-0002 — Short authenticator secrets (≤16 bytes raw)
**Status:** done  
**Proof obligation:** 10-byte secrets (e.g. `JBSWY3DPEHPK3PXP`) match standard TOTP even when heap after the secret is non-zero.  
**Evidence:** host tests “short-key+garbage differs” (buggy path) and “fixed path ignores garbage”.

### STORY-0003 — Embedded NUL in key material
**Status:** done  
**Proof obligation:** Keys containing interior `0x00` use full length, not C-string truncation.  
**Evidence:** embedded-NUL host tests.

### STORY-0004 — RFC 6238 SHA-1 vectors
**Status:** done  
**Proof obligation:** Seed `12345678901234567890` produces appendix-B 8-digit codes for documented timestamps.  
**Evidence:** RFC6238 host cases.

### STORY-0005 — Toolchain/vendor hygiene
**Status:** done  
**Proof obligation:** `hmac-sha1` is in-tree source (not empty gitlink); unused `hmac_1` removed; host and PSP builds work.  
**Evidence:** tree layout; `make host-test`; optional `make` with pspdev.

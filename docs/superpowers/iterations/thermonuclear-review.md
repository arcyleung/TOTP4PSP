# Thermonuclear code-quality review — TOTP4PSP

**Branch:** `fix/totp-secret-length-hmac-key`  
**Base:** `main` @ b0a5e76  
**Review style:** cursor-thermonuclear  
**Date:** 2026-07-02  

## 1. Executive summary

### APPROVE-WITH-FIXES → **APPLIED**

Core fix sound: exact `secret_len`, no `strlen` on secrets, vendored HMAC-SHA1, RFC + regression tests.

Must-fix applied post-review:
- **MF-1** digits clamped via `totp_clamp_digits` / `mod_hotp` (6..8); host coverage for 0/99.
- **MF-2** invalid/empty base32 secrets freed and skipped (no empty-key live codes).
- **Test contract** `totp_decode_secret_b32` is the shared shipped path for base32→len.
- Untracked `EBOOT.PBP` / `totp_4_psp.elf` from git index (still built locally).
- UI uses `calc_totp` as single entry.

## 2. Must-fix (status)

| ID | Issue | Status |
|----|-------|--------|
| MF-1 | Unclamped digits / sprintf overflow | **Fixed** |
| MF-2 | Failed decode still shown | **Fixed** |
| M1-tests | secret_len contract host coverage | **Fixed** (`totp_decode_secret_b32`) |
| M2-tests | Tautological assert | **Replaced** |

## 3. Structural notes (non-blocking remaining)

- `algorithm` stored unused (SHA1 only) — deferred product TODO.
- `issuer` not drawn — deferred.
- `lookup()` hash for 5 fixed param names — fine.
- Vendor `hmac-sha1` left mostly untouched (third-party).

## 4. Files reviewed

main.c, totp_core.c/h, tests/test_totp.c, Makefile, hmac-sha1/**, hmac_1 removal, .gitignore, README.md, graphics.c string.h

## 5. Subagent outcomes

- Thermonuclear subagent: approve-with-fixes (MF-1, MF-2).
- Test-compat subagent: crypto path PASS; main wiring gap → closed via `totp_decode_secret_b32`.

## 6. Sentinel

`make host-test` — 30 passed, 0 failed (post must-fix).

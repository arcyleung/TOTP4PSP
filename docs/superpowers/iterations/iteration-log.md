# Iteration log

## ITER-0000 — Walking skeleton (2026-07-02)
**Delivered**
- Root cause: short secrets forced HMAC key length 21 (heap garbage) and `strlen` on binary secrets.
- Fix: store `secret_len` from `base32_decode`; `calc_hotp(secret, secret_len, counter)`.
- Vendor `hmac-sha1/src`; delete empty submodule + unused `hmac_1/`.
- Host tests at real entry `make host-test`.
- Commit `790d7c6` on `fix/totp-secret-length-hmac-key`; pushed to origin (HTTPS after SSH key denial).

**Scenarios closed:** SCEN-0001..0004  
**Notes:** Not a compiler/HMAC-lib bug; application key-length handling.

## ITER-0001 — Thermonuclear review (started)
- Subagent review of net code changes vs main.
- Findings and remediations recorded in thermonuclear review artifact.

## ITER-0002 — PR (pending final packaging)

## ITER-0001 — Thermonuclear review + must-fix (2026-07-02)
**Subagents**
- Thermonuclear review (read-only): approve-with-fixes MF-1 digits clamp, MF-2 skip bad secrets.
- Test-compat audit (execute): 19→ then 30 pass after fixes; flagged main wiring coverage gap.

**Applied**
- `totp_clamp_digits`, defensive `mod_hotp`, `totp_decode_secret_b32` in `totp_core`.
- `main.c` uses clamp + decode helper; skips invalid secrets; `calc_totp` for display.
- Host tests: digits clamp, decode contract, invalid b32 reject.
- Untracked EBOOT/elf from git index.
- Review artifact: `docs/superpowers/iterations/thermonuclear-review.md`.

**Sentinel:** `make host-test` 30 passed, 0 failed.

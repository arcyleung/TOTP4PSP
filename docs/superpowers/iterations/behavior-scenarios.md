# Behavior scenarios — TOTP4PSP secret-length fix

## SCEN-0001 — RFC6238 T=59 eight-digit code
- **ID:** SCEN-0001
- **Journey:** offline TOTP display for RFC seed
- **Given** secret bytes ASCII `12345678901234567890`, counter `floor(59/30)=1`, digits=8
- **When** `calc_totp` / HOTP mod path runs
- **Then** code is `94287082`
- **Command:** `make host-test` (asserts in `tests/test_totp.c`)
- **Seam:** unit / `totp_core`
- **Cadence:** sentinel

## SCEN-0002 — Short key with heap garbage (pre-fix regression)
- **ID:** SCEN-0002
- **Given** 10-byte decoded secret and non-zero bytes past length
- **When** fixed path uses `secret_len=10` and historical buggy path forces key length 21
- **Then** fixed code matches pure-length-10 HMAC; buggy path differs when garbage is non-zero
- **Command:** `make host-test`
- **Seam:** unit + differential against historical buggy harness in test file
- **Cadence:** sentinel

## SCEN-0003 — Embedded NUL secret
- **ID:** SCEN-0003
- **Given** binary secret with interior 0x00
- **When** full length vs strlen-truncated length are used
- **Then** full-length OTP differs from truncated; fixed path uses full length
- **Command:** `make host-test`
- **Cadence:** sentinel

## SCEN-0004 — HMAC-SHA1 library sanity (RFC 2202 case 1)
- **ID:** SCEN-0004
- **Given** key 20×0x0b, data `Hi There`
- **When** vendored `hmac_sha1` runs
- **Then** digest matches RFC 2202 test vector
- **Command:** `make host-test`
- **Cadence:** sentinel

## SCEN-0005 — PSP EBOOT links (optional)
- **ID:** SCEN-0005
- **Given** pspdev on PATH
- **When** `make`
- **Then** `EBOOT.PBP` produced
- **Command:** `export PATH="$PSPDEV/bin:$PATH"; make`
- **Cadence:** manual / when toolchain present

# Behavior corpus index

| Scenario | Seam | Cadence | Command | Status |
|----------|------|---------|---------|--------|
| SCEN-0001 RFC6238 T=59 | totp_core via make host-test | sentinel | `make host-test` | green |
| SCEN-0002 short+garbage | totp_core + buggy differential | sentinel | `make host-test` | green |
| SCEN-0003 embedded NUL | totp_core | sentinel | `make host-test` | green |
| SCEN-0004 RFC2202 HMAC | hmac-sha1 | sentinel | `make host-test` | green |
| SCEN-0005 PSP EBOOT | full link | optional | `make` with pspdev | when toolchain available |

Sentinel suite entry point: **`make host-test`** (real shipped `totp_core` + vendored crypto + `tests/test_totp.c`).

# Roadmap

## ITER-0000 — Walking skeleton: correct TOTP for real secrets (DONE)
- secret_len path, totp_core, host tests, vendor hmac-sha1, remove dead crypto/submodule.
- Closes SCEN-0001..0004.
- Commit `790d7c6` on `fix/totp-secret-length-hmac-key`.

## ITER-0001 — Thermonuclear review + must-fix (DONE)
- Adversarial maintainability review of net diff.
- MF-1 digits clamp, MF-2 skip invalid secrets, decode contract tests.
- Sentinel green (30/30).

## ITER-0002 — PR packaging (IN PROGRESS)
- Commit iteration artifacts + review fixes.
- Push branch; `gh pr create` against `main`.

## Deferred (out of goal scope)
- SHA-256/SHA-512 algorithms
- Issuer UI display
- On-device PSP validation

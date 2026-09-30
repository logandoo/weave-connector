---
type: fix
trust: ⏳ Unverified (e2e green 2026-09-28; awaiting user confirmation)
updated: 2026-09-28
---
# Credential reference layer (password_ref)

Change-wave: resolve-below-the-model creds for weave-connector. commit: 2c1d2d3.

- `password_ref = "env:VAR" | "keychain:service/account"` resolved at connect (asyncio.to_thread), fail-closed, audit.jsonl (0600, O_NOFOLLOW) names-only.
- scrub_text: raw/hex/b64/b64url, PTY-wrap tolerant (the tty inserts " \r" INSIDE long secrets at wrap columns — exact matching fails there), window-edge fragment trim, middle-slice rule. Values ≥4 chars registered for both password and password_ref paths.
- Config perm warning (mode in reload fingerprint; chmod-only changes detected).
- ❌→✅ pitfalls recorded in fix_asyncssh_server_session.md style: tuple-vs-int mtime compare TypeError; max_bytes clamped to 200 defeated split tests; wrap-noise broke exact scrub (root cause found via raw pty hexdump).
- ⛔ action for user: rotate the LAN password that briefly entered git history (D-7: tree redacted, history untouched; public copy never contains it).

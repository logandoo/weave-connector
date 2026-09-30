---
type: fix
trust: ⏳ Unverified (e2e green 2026-09-29; awaiting user confirmation)
updated: 2026-09-29
---
# Backlog sweep: daemon + key vault + transcripts + small fixes

commit: d60d2fa..HEAD. 11/11 + 52/52 + 50/50 + 8/8 = 121 checks.

- Resident daemon (~/.weave-connector/daemon.sock, token 0600, flock
  single-instance): sessions/cursors/forwards survive MCP client restarts —
  proven by test_daemon kill-restart. MCP server = thin client (flat Manager
  RPC surface, per-call connections = concurrent-safe); auto-spawn; auto-
  respawn+retry on ConnectionError; WEAVE_CONNECTOR_DAEMON=off for in-process.
- Key vault: key_ref = keychain:service/account holds PEM; enroll kind="key"
  source="file:<path>" (confirm-gated); ALL keychain writes via python-keyring
  (Security.framework) — the `security -w` argv fallback was REMOVED (fail-
  closed). Pitfall: secrets live in the DAEMON process — scrub must run there
  (errors scrubbed at source in daemon.handle), not only in the MCP client.
- Transcripts: record=true; scrub-AT-RECORD (raw secrets never stored),
  5000-event/4MB caps, exec payloads included, max_bytes clamped.
- Pitfalls fixed this wave: name-reservation poison (prune must discard
  reservations; validate before reserve; guarded creation zone); 64KB
  asyncio stream default limit breaks >64KB RPC lines (set limit=16MB);
  JSON escape inflation 6x on binary (keep payload clamps well under line
  limit); per-call connections needed because a shared stream serializes
  (signal-behind-exec deadlock).

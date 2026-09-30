---
type: fix
trust: ⏳ Unverified (e2e green 2026-09-28; awaiting user confirmation)
updated: 2026-09-28
---
# P0 wave: SFTP + risk gate + host-key pinning + skill pack

commit: 6d021fd (+ 9ea1e95 review package). 34->36 e2e checks, 52 classifier cases.

- SFTP: 5 tools over the persistent connection (asyncssh native). Mutations are
  MODIFY-class (confirm required, gate-time audit), download refuses local
  clobber unless overwrite=True, read clamped 16MB + truncated flag.
- Risk gate (risk.py, D-9): READ/CREATE free; MODIFY anchored to command
  position + system-path redirects only; SERVICE/DELETE/PRIVILEGE unanchored +
  case-insensitive (noise accepted, safe direction). sh -c wrappers = MODIFY.
  Bootstrap exec uses _internal=True (server-internal, injection-safe quoting).
- Host key: host_fingerprint="SHA256:..." pins via SSHClient.validate_host_public_key
  at KEX (pre-auth). CRITICAL pitfall: known_hosts={} is FALSY — asyncssh then
  falls back to ~/.ssh/known_hosts and a pre-trusted key bypasses the pin; use
  known_hosts=asyncssh.import_known_hosts("") (truthy empty) so the pin is the
  sole trust root.
- audit.jsonl: exec_blocked/exec_confirmed carry scrubbed command text; raw_write,
  all sftp ops + blocked variants recorded.
- SSH test server: process_factory + sftp_factory=True (server_factory
  session_requested path CANNOT serve sftp_factory).

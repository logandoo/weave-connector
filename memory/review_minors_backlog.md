---
type: project
trust: ⏳ Unverified (deferred minors from 2026-09-27 adversarial review)
updated: 2026-09-27
---
# Deferred Minor findings (A4.9 review, adjudicated → backlog)

- TOFU persistence for `accept_unknown_host` keys; warn when both accept_unknown_host and known_hosts set.
- chmod check on config.toml (contract says 600; repo copy is 0644 with lab-only creds).
- `ssh_shell_read(cursor=0)` on a fresh session reports data_loss (bootstrap hidden) — cosmetic contract nuance.
- Two concurrent `ssh_shell_await` calls can both report one marker (benign, uncontracted).
- Idle reaper: connections with zero sessions are never reaped; sessions with constant output (top) never idle out.
- Test gaps: idle-reaper firing, reconnect-after-drop, MAX_SESSIONS cap, parallel-safe ports.
- SFTP tools deliberately out of scope (D-4).
- Tier-2 minors (2026-09-27): companion reads are attestation-based; evidence-mtime anomaly after commit 0fb3a61; verification_log iter 7 says 15/15 while final is 21/21 (cosmetic).
- Scrub residuals (2026-09-28 re-review): whitespace-containing secrets bypass fragment rules; self-overlap leaves ≤3-char residue; SCRUB_MIN_LEN=4 over-scrubs short values (accepted fail-safe); pre-existing audit.jsonl keeps old file mode; standard-b64-unpadded form not covered.
- e2e session_isolation assertion `"/var" not in pwd` is cwd-sensitive (sandbox tmp paths) — pre-existing, untouched.
- P0 re-review residuals (2026-09-28): NEW-F pin-fallback regression test would need seeding ~/.ssh/known_hosts (invasive — deferred; unit-level truthy-known_hosts check stands in); NEW-G _conn_ident omits known_hosts path + password value (presence bit only); NEW-H audit.jsonl cwd-relative path + fail-open-on-write-failure documented only in code comments.
- P0 round-2 minors (2026-09-28, all fail-safe direction): unanchored sort -o / kill tokens fire in arg positions (prompt friction, not bypass); IGNORECASE widens FP surface (echo Sudo -> PRIVILEGE); wrap-set misses fish -c; target-set asymmetry (/var, /home/u/.profile, $HOME/backup.txt ungated); `su` token FP (ls su.txt).
- P1+P2 round-3 minors: name-only reuse has theoretical TOCTOU on concurrent same-name open_shell (single-client MCP is sequential in practice); enroll dialog error conflates user-cancel vs no-GUI (stderr discarded); sessions.json persist skips repair of an already-corrupt file (best-effort by design); security -w argv brief ps exposure (Security.framework would fix).
- Backlog-sweep residuals (2026-09-29, all non-blocking): C2 same-process ConnectionError retry path is code-verified only (post_stop_recovery nets respawn-at-entry); RPC JSON escape inflation leaves ~2.7MB binary sftp_read ceiling (clamped 2MB, chunking deferred); silent fallback to in-process mode when daemon fails to start (AF_UNIX path limits) could warn; `type(b).__name__` check is fragile; enroll kind-check cosmetics; sftp_download symlink race with overwrite=True (same-user threat).

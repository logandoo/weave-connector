> cap=5  stall=3×

1. `ssh_list_profiles` lists configured profiles without exposing passwords/keys.
2. `ssh_shell_open` returns a session_id backed by a real SSH channel + PTY shell.
3. `cd` in one `ssh_shell_exec` persists into the next exec on the same session.
4. `export` in one exec persists into the next exec on the same session.
5. `ssh_shell_exec` returns the correct exit code (0 for true, 1 for false).
6. A long-running command with short timeout_ms returns `timeout: true` and keeps running; `ssh_shell_await` later returns its output + exit code.
7. `ssh_shell_signal interrupt` (Ctrl-C) kills a foreground `sleep` (exit code 130).
8. `ssh_shell_write` raw input + `ssh_shell_read` with cursor returns the new output incrementally.
9. Two sessions on one connection have independent shell state.
10. Closing one session keeps the SSH connection and other sessions usable.
11. Unknown session_id returns a clean error, not a crash.
12. Server runs as a stdio MCP server driven by a real MCP client (no hand-rolled JSON-RPC).
13. PTY resize propagates to the remote tty (`stty size` reflects new dimensions).
14. Command output containing a fake marker cannot spoof the exit code (nonce-bound markers).
15. Wedge-prone commands (trailing `&`, `|`, `\`, multi-line) are rejected with a clear error and the session stays usable.
16. A session wedged by an unterminated quote recovers via `ssh_shell_reset` and accepts new execs.
17. `ssh_shell_write` accepts base64 exact bytes.
18. Writing to a closed session returns a clean error.
19. (from review) Remote shell history is disabled on bootstrap; secrets in `env` never appear in tool errors.
20. (change-wave 2) A profile added to config.toml while the server runs is listed and connectable without a server restart (hot-reload).
21. (change-wave 3) A profile with `password_ref = "env:VAR"` authenticates when VAR is set; no plaintext password in config.toml.
22. (change-wave 3) A profile with `password_ref = "keychain:service/account"` authenticates using a macOS Keychain value.
23. (change-wave 3) An unresolvable ref fails closed with an error naming the ref and containing no secret material.
24. (change-wave 3) Secret values used for authentication (>=8 chars) are scrubbed from shell output returned to the model (raw + base64 forms).
25. (change-wave 3) An audit trail records ref resolution (ref name + profile + host, never values).
26. (change-wave 3) A config.toml containing credentials with group/world-readable perms triggers a warning visible via ssh_status.
27. (change-wave 4) SFTP round-trip over the persistent connection: write/read/list/upload/download all succeed (e2e sftp_roundtrip).
28. (change-wave 4) Commands classified MODIFY/SERVICE/DELETE/PRIVILEGE are refused without confirm=True and run with it (e2e risk_gate_confirm + 20 classifier unit cases).
29. (change-wave 4) host_fingerprint pinning: wrong SHA256 refused fail-closed pre-auth, correct fingerprint connects (e2e host_fingerprint_pin).
30. (change-wave 4) SKILL.md carries the risk-level table + call budget + subagent discipline + host-key guidance (e2e skill_risk_pack doc check).
31. (change-wave 5) Named sessions: ssh_shell_open(name="X") twice returns the same session_id; ssh_shell_list shows the name.
32. (change-wave 5) ssh_forward_open starts a local port forward through the SSH connection; a TCP client on the local port reaches a service; forward_list/forward_close work.
33. (change-wave 5) ProxyJump: a profile with jump="<other-profile>" connects through the jump connection and exec works.
34. (change-wave 6) ssh_credential_enroll writes a password into the Keychain via a restricted source (dialog or env:WEAVE_ENROLL_*); a password_ref profile then authenticates; the value never appears in tool args or outputs.
35. (change-wave 5) MCP tool annotations present: read-only tools readOnlyHint, destructive tools destructiveHint (via tools/list).
36. (change-wave 5/6) All prior criteria stay green (regression).
37. (change-wave 7) Daemon persistence: a shell session opened through one MCP server process is still alive and usable through a NEW MCP server process after the first is killed (sessions live in the daemon).
38. (change-wave 7) keyring backend stores/fetches keychain values (no `security -w` argv path in the default store); existing `security`-seeded items interop (get works).
39. (change-wave 7) key vault: profile key_ref resolves a PEM from keychain and authenticates (public-key auth); enroll kind="key" source="file:<path>" stores it without the value entering tool args.
40. (change-wave 7) Transcripts: opt-in record on shell_open; ssh_shell_transcript returns scrubbed history (registered secret values absent).
41. (change-wave 7) Small-fix bundle holds: TOCTOU name reservation under concurrent open; dead sessions pruned before cap; corrupt sessions.json self-repairs; enroll dialog reports cancel vs no-GUI distinctly; audit+sessions.json live under the state dir; scrub covers std-b64-unpadded + whitespace-condensed forms.
42. (change-wave 7) All prior criteria stay green (regression).
43. (change-wave 8) vault: refs resolve from the local secrets file (0600); ssh_credential_enroll stores to the vault and returns a vault: ref; no keychain/keyring call in the default path.
44. (change-wave 8) The whole suite performs zero keychain operations (no `security` CLI, no keyring) — no login-password prompts are possible.
45. (change-wave 8) All prior criteria stay green (regression).


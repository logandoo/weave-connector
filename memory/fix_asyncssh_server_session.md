---
type: fix
trust: ✅ Verified
updated: 2026-09-27
---
# asyncssh test-server pitfalls (❌ attempts → ✅ fix)

Problem: local integration SSH server reset connections when a client requested an interactive shell.

- ❌ `asyncssh.listen(..., session_factory=TestSession, encoding=None)` — encoding/stream wrapper called the factory as `(stdin, stdout, stderr)` → TypeError, silent connection reset.
- ❌ same with `session_factory` even without encoding — `line_editor` wraps PTY sessions by default.
- ✅ override `SSHServer.session_requested()` returning the session, and pass `line_editor=False` to `listen()`.
- ❌ Ctrl-C (`\x03`) did not kill foreground processes: bash spawned with inherited slave fds never owned the pty (dup2 ≠ open) → no foreground process group.
- ✅ `preexec_fn`: `os.setsid()` + `ioctl(0, TIOCSCTTY, 0)` in the child.
- ❌ Two-line exec marker (`cmd\nprintf MARKER\n`) lost on Ctrl-C: VINTR flushes the tty input queue.
- ✅ single-line payload `cmd; printf '\n__WC_EXIT_%s__\n' "$?"` — bash continues the list after SIGINT, marker reports 130.
- ❌ `await_pending` matched stale markers from earlier execs (searched from buffer base).
- ✅ track `_pending_start` per exec; search from there.
- ❌ 2026-09-27: killing the opencode-hosted weave-connector MCP process mid-session permanently removes its tools from that session (opencode does not respawn dead stdio MCP servers); after that, tool calls cannot dispatch. Restart the opencode session (or /mcp reconnect) instead of killing the process. Config edits need NO restart since hot-reload (mtime) landed in 1a4d1b2-era commit "feat: config hot-reload".

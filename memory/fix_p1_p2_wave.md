---
type: fix
trust: ⏳ Unverified (e2e green 2026-09-29; awaiting user confirmation)
updated: 2026-09-29
---
# P1+P2 wave: forwards, ProxyJump, named sessions, enroll, annotations

commit: 1e88fce..6a3174d. 47/47 e2e, 52/52 risk, 10/10 resolver.

- Port forwards (-L): ssh_forward_open/list/close, loopback-only unless
  confirm=True, cap 16, registry cleaned on disconnect/shutdown, audited.
- ProxyJump: profile `jump = "<profile>"` via asyncssh tunnel=; cycle/depth-8
  validation BEFORE locks (non-reentrant lock = permanent deadlock otherwise).
- Named sessions: shell_open(name=...) idempotent; name-only reuse (unique
  alive name) is a feature; explicit different profile refused; sessions.json
  = best-effort hints (env KEYS only, 0600, atomic, untracked, never bricks).
- Enroll: ssh_credential_enroll — dialog script is a FIXED literal (profile
  names interpolated into AppleScript = RCE), name allowlist ^[A-Za-z0-9_.-]+$,
  value registered for scrub BEFORE keychain store (timeout/argv can't leak),
  dialog timeout 120s + kill; env source strictly env:WEAVE_ENROLL_*.
- Annotations: destructiveHint on write/signal/reset/enroll/disconnect/close/
  forward_close/exec; readOnlyHint on reads.
- Test-server: SSHServer.connection_requested must return True for
  direct-tcpip (forwards + jump tunnels), else "Connection refused".

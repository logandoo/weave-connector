---
type: fix
trust: ⏳ Unverified (e2e green 2026-09-29; awaiting user confirmation)
updated: 2026-09-29
---
# Vault-file credential store (D-12) — keychain REPLACED

Trigger: macOS login-keychain ACL prompted for the user's password on every
new process touching a keychain item (tests, daemon). User: "不要直接保存到
keychain 中！不要输密码！"

- DEFAULT store = local vault file $WEAVE_CONNECTOR_STATE_DIR/secrets.json
  (or ~/.weave-connector/secrets.json), 0600, atomic unique-tmp writes,
  O_NOFOLLOW reads, corrupt file fail-closed (no clobber).
- Ref schemes: vault:NAME (default) | env:VAR | keychain:svc/acct (EXPLICIT
  opt-in only — keyring touch only if a profile actually uses it).
- enroll -> vault (returns vault:<profile> refs); password file: source is
  confirm-gated + path-audited; kind=key file: source likewise.
- Suite performs ZERO keychain operations (no security CLI, no keyring) —
  password prompts are structurally impossible during tests.
- Real user profiles migrated keychain->vault via one CLI read (no prompt);
  that was the LAST keychain touch. If prompts ever appear again, look for a
  leftover keychain: ref in config.

---
type: reference
trust: ✅ Verified (web research 2026-09-28, S1 spike — no code)
updated: 2026-09-28
---
# Credential vault research for weave-connector (spike outcome)

SOTA pattern: resolve-below-the-model — agent holds only a NAME/reference; a sub-model
layer resolves and injects at point of use; plaintext never enters context/logs.

Mature refs: agent-vault (mvplab-ai: AES-GCM vault, master key in OS keychain, per-secret
host allowlist, output scrubbing raw/base64/urlenc, append-only audit), secrets-mcp
(DatanoiseTV: keychain master key, native password dialog entry, PreToolUse guard on vault
dir, PEM line-wise scrub), wundervault (SSH keys from vault never on disk, tiered human
approval), AWS asm-exec ("plaintext never enters the agent's context window"),
MCP SEP-2779 (config credential refs op:// keychain://, fail-closed, memory-only).

Chosen design (if implemented):
1. macOS Keychain as the store (security add/find-generic-password); no self-rolled crypto.
2. config.toml holds password_ref="keychain:svc/acct" or "env:VAR"; resolved at connect
   inside the server process; fail-closed.
3. Scrub resolved secret values (raw+base64) from _clean/read output.
4. ref bound to its profile host (anti injection-swap).
5. Audit: stderr/file log of ref-use (name+host, never value).
6. config.toml perm != 600 → warning; prefer key+ssh-agent over passwords.

Honest boundary: protects model context/transcripts/logs; NOT a defense against a local
process already running as the user (it can read the keychain too).

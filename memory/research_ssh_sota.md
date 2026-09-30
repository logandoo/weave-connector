---
type: reference
trust: ✅ Verified (web research 2026-09-28, S1 spike — no code)
updated: 2026-09-28
---
# SOTA SSH MCP + SSH skill survey (2026-09-28)

Surveyed: slepp/ssh-mcp, jaenster/remote-shell-mcp, xunuo2345/ssh-mcp-toolkit,
mcp-remote-ssh (pypi), d3v1an/ssh-mcp, bhayanak/ssh-server-mcp, mcp-ssh-tool,
xcdd/Agent-SSH-MCP, badseal/ssh-skill, brewtools/ssh (brewcode), Eriemon/remote-ssh,
MCP spec 2026-07-28 (elicitation/MRTR/tool annotations/outputSchema/Tasks).

We lead on: wrap-tolerant scrub + window-fragment protection (unique), fail-closed
keychain/env refs, localhost-out-of-scope rule, marker exit codes + cursor stream.

Gaps ranked:
P0: SFTP ops (universal in SOTA; write_remote = no quoting pitfalls) · destructive-cmd
risk classes + confirm gate (brewtools READ/CREATE/MODIFY/SERVICE/DELETE/PRIVILEGE;
d3v1an confirm+undo) · host-key fingerprint pinning (strict/accept/ask modes).
P1: daemon persistence of sessions across MCP restart (remote-shell-mcp — fixes the
kill-process-loses-tools failure) · port-forward as separate permission-gateable tool
(slepp; block -L/-R in extra args) · ProxyJump profile field · tool annotations +
outputSchema + progress notifications.
P2: elicitation URL-mode credential enrollment (spec: form mode MUST NOT collect
passwords) · session transcripts + detached tmux observer · named sessions recoverable
across conversations (slepp session_name).

Skill-layer lessons: risk-class table in SKILL.md; read-only query batching + call
budget (5-15); one bounded unit per subagent spawn, destructive approval never
delegated; Chinese trigger keywords; Codex 1024-char description cap; references/
split to keep SKILL.md lean.

Suggested order: SFTP → risk classes + host key → skill discipline pack → forward/
jump/protocol hygiene → elicitation enrollment.

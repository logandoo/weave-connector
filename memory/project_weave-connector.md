---
type: project
trust: ✅ Verified
updated: 2026-09-27
---
# weave-connector project

- MCP server (Python 3.13 venv, mcp<2 FastMCP, asyncssh) over stdio; registered in `opencode.json`.
- Profiles in `config.toml`; secrets never in tool args; `accept_unknown_host` only for lab.
- Core invariants: sentinel marker `__WC_EXIT_<n>__` for exit codes (single-line `; printf` form — survives Ctrl-C tty flush); absolute cursor offsets over capped ring buffer; ≤1 pending exec per session; ≤32 sessions.
- Tests: `bash script/linux/run_tests.sh` → real asyncssh server + real PTY/bash on 127.0.0.1:10022 (profile `local-test`). Evidence in `tests/evidence/`.
- Lifecycle ONLY via `script/linux/*.sh` (build/start/stop/restart/run_tests).
- Companion skill: `.opencode/skills/ssh-connector/SKILL.md`.
- Deferrals: SFTP tools out of scope (D-4); node-pty/raw-screen fidelity (D-1); global skill install (D-2).

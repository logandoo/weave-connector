# weave-connector

**MCP server that gives AI agents persistent, interactive SSH shell sessions** — one
long-lived SSH channel per host, N PTY shells on top, real exit codes, cursor-streamed
output, SFTP, port forwarding, ProxyJump, and a credential model where **secrets never
enter the LLM context and never touch the login keychain** (zero password prompts).

Built with Python: [FastMCP](https://github.com/modelcontextprotocol/python-sdk) (stdio) +
[asyncssh](https://github.com/pyca/asyncssh). No native deps, no sshpass.

## Why

Agents operating on remote servers usually re-dial SSH per command (`sshpass -p … ssh host "cmd"`)
or drive one-shot exec channels: state (`cd`, `export`, a running `vim`) is lost between calls,
interactive programs are undrivable, and credentials leak into model-visible arguments.
weave-connector inverts this: **connect once, keep a real terminal, work on it**.

## Capabilities

| Area | What you get |
|---|---|
| Persistent shells | PTY sessions that survive across tool calls: cwd, env, virtualenvs, running TUIs |
| Command completion | Sentinel-marker protocol returning **real exit codes** (survives Ctrl-C) |
| Long-running work | Short-timeout exec → incremental cursor reads (long-poll) / `await` / Ctrl-C |
| Interactive & TUI | Raw base64 writes, control signals (Ctrl-C/D/Z/\), resize, `reset` to un-wedge |
| Credentials | Local vault file (`~/.weave-connector/secrets.json`, 0600) — zero keychain prompts; `env:` refs; keychain: opt-in; private keys in vault (`key_ref`); enrollment via below-model sources |
| Output protection | Secret scrubbing (raw/hex/base64, PTY-wrap-tolerant, split-window safe) on every egress path |
| Safety | Risk-tier gate (READ/CREATE free; MODIFY/SERVICE/DELETE/PRIVILEGE need `confirm:true`, audited) |
| Host keys | `host_fingerprint` pinning verified **pre-auth** (fail-closed) |
| Files | SFTP list/read/write/upload/download (write-class gated; download no-clobber by default) |
| Network | Local port forwards (`-L`, independent tool = permission-gateable) · ProxyJump via `jump = "<profile>"` |
| Durability | Resident **daemon** (`daemon.sock`): sessions survive MCP client restarts; named sessions for idempotent reuse; opt-in scrubbed transcripts |
| Audit | `audit.jsonl` (0600): ref uses, blocked/confirmed commands, SFTP ops, enrolls — names/paths, never values |

## Architecture

```
opencode.json  (mcp.weave-connector → stdio)
```

### Component / flow diagram

```mermaid
flowchart LR
    subgraph Client
        LLM[LLM / agent<br/>sees names, refs, cursors —<br/>never secret values]
    end

    subgraph MCPClient[MCP client host]
        SK[ssh-connector skill<br/>risk tiers · budgets · playbook]
    end

    subgraph Stdio[weave-connector · stdio MCP server]
        TOOLS[FastMCP tools<br/>ssh_shell_* · ssh_sftp_* · ssh_forward_*<br/>ssh_credential_* · ssh_daemon_*]
        SAFE{"safe() error scrub<br/>uniform {error} shape"}
    end

    subgraph Daemon[Resident daemon · daemon.sock<br/>(owns connections; survives client restarts)]
        DIS{dispatch<br/>allowlisted methods<br/>token auth · scrubbed errors}
    end

    subgraph Core[Manager]
        CM[ConnectionManager<br/>per-profile SSHClientConnection<br/>keepalives · identity-keyed reuse<br/>jump chains · hot-reload fingerprint]
        SESS[ShellSession ×N<br/>PTY process · ring buffer + cursors<br/>nonce marker protocol · transcript<br/>idle reaper]
        SFTP[SFTP client (per op)]
        FWD[Port-forward registry<br/>-L listeners · cap/loopback guard]
    end

    subgraph Creds[Credential layer — below the model]
        RES["SecretResolver<br/>vault: · env: · keychain: (opt-in)"]
        V[("secrets.json<br/>0600 atomic vault")]
        SC[scrub engine<br/>raw/hex/b64 · wrap-tolerant<br/>split-window safe]
      AUD[("audit.jsonl · 0600<br/>names/paths only")]
    end

    subgraph Remote[Remote host]
        SSHD[sshd] --> BASHB[in-shell bash on PTY]
    end

    LLM -->|tool calls by NAME/REF/cursor| SK --> TOOLS --> SAFE
    TOOLS -->|RPC: unix socket,<br/>token, per-call conn| DIS
    DIS --> CM & SESS & SFTP & FWD
    CM -->|asyncssh<br/>password/key resolved in-process<br/>host-fingerprint pinned pre-auth| SSHD
    SESS <--> BASHB
    RES --> V
    TOOLS -.resolve at connect.-> RES
    SESS -.all egress.-> SC
    CM & SESS & SFTP & FWD -.audit.-> AUD
```

### Persistent shell & completion protocol

```mermaid
sequenceDiagram
    participant A as Agent (LLM)
    participant T as MCP tools (stdio)
    participant D as Daemon / Manager
    participant S as ShellSession (PTY + bash)

    A->>T: ssh_shell_open(profile, name?, cwd?, env?)
    T->>D: open_shell
    D->>D: resolve vault:/env: ref IN-PROCESS · register for scrub · audit
    D->>S: create PTY shell · disable remote history
    S-->A: session_id (+cursor)

    Note over A,S: long-running command
    A->>T: ssh_shell_exec(sid, "deploy", timeout_ms=800)
    T->>D: risk-tier gate (confirm? · audit)
    D->>S: write: deploy; printf \n__WC_EXIT_<nonce>_%s__\n "$?"
    S-->>D: stream → ring buffer (cursor offsets)
    D-->>A: {timeout:true, cursor}   % still running
    A->>T: ssh_shell_read(sid, cursor, wait_ms)   % incremental, scrubbed
    T-->>A: {output, cursor, data_loss}
    A->>T: ssh_shell_await(sid)
    S-->>D: marker __WC_EXIT_<nonce>_0__
    D-->>A: {completed, exit_code, output}

    Note over A,S: interrupt
    A->>T: ssh_shell_signal(sid, interrupt)
    T->>S: \x03 — single-line marker survives tty flush (VINTR)
    S-->>A: exit_code 130 via await
```

### Secrets flow (why no prompts, no LLM exposure)

1. **At rest**: vault file `secrets.json` (0600, atomic, corrupt-safe) — not the login keychain, so macOS never raises a keychain ACL password dialog.
2. **At resolve**: `SecretResolver` reads `vault:`/`env:` inside the daemon process at connect time; plaintext exists only in that process's memory and is registered for scrubbing. `fail-closed` on every error.
3. **At use**: password/private key handed straight to asyncssh — never in tool arguments or config plaintext (config holds the *ref*).
4. **At egress**: every output path (exec/read/transcript/SFTP/error text) passes the scrub engine, which tolerates PTY line-wrap noise and split read-windows so fragments can't leak across cursor reads.

## Quick start

```bash
bash script/linux/project_build.sh     # venv + deps (Windows: script\windows\project_build.bat)
```

Add a host — credentials into the vault (never into the file):

```toml
# config.toml  (chmod 600)
[profiles.web]
host = "203.0.113.10"
username = "deploy"
password_ref = "vault:web"       # or: env:MY_VAR | key = "~/.ssh/id_ed25519"
jump = "bastion"                 # optional ProxyJump (another profile)
host_fingerprint = "SHA256:..."  # optional host-key pin
```

Enroll via the agent: `ssh_credential_enroll(profile="web", source="dialog")` opens a
native hidden-input prompt (only when you ask) — the value goes straight to the vault.

Register the MCP server (opencode example; any MCP client works):

```json
{ "mcp": { "weave-connector": {
    "type": "local",
    "command": ["<repo>/.venv/bin/python", "-m", "weave_connector.server"],
    "environment": { "WEAVE_CONNECTOR_CONFIG": "<repo>/config.toml" },
    "enabled": true } } }
```

Agent playbook: `.opencode/skills/ssh-connector/SKILL.md` (risk tiers, call budgets,
named sessions, long-running pattern).

## Security model — what it does and does not guarantee

| Guarantee | How |
|---|---|
| Secrets never in model context | refs only in tool args; resolve below the model; scrub on all egress |
| No keychain password prompts | local vault file as default store |
| Host-key integrity | fingerprint pin verified at KEX, pre-auth, fail-closed; `~/.ssh/known_hosts` otherwise |
| Destructive discipline | risk-tier gate + `confirm` + audit; kernel-level stop-signal for agents in the skill |
| Auditability | name/path-only `audit.jsonl`, 0600, `O_NOFOLLOW` |
| **Not** a sandbox | it raises the bar for the *model/LLM/logs* threat. A process already running as your user can read the vault (that's the trust boundary it operates under). |

Honest residuals (see `memory/review_minors_backlog.md`): transformed-secret defensive
scrub limits, per-call daemon RPC line budget, same-uid trust boundary.

## Repository layout

```
src/weave_connector/
  server.py     FastMCP tool surface · uniform error shapes · annotations
  session.py    Manager: connections · ShellSession (marker/cursor/transcript)
                SFTP · forwards · named sessions · enroll
  daemon.py     resident daemon: unix-socket RPC · token · single-instance flock
  risk.py       command risk classifier (READ/CREATE/MODIFY/SERVICE/DELETE/PRIVILEGE)
  config.py     profiles · SecretResolver · vault store · scrub engine · audit
tests/          acceptance-driven suites (real asyncssh SSHD + PTY + SFTP + jump + daemon)
script/         script-only lifecycle: build/start/stop/restart/run_tests
docs in *.html  FLOW_DESIGN · BACKEND_DESIGN · DATABASE_DESIGN
memory/         engineering memory (pitfall logs from real review rounds)
```

## Testing

```bash
bash script/linux/run_tests.sh
```

Real crypto, real SSH, real PTY: the suite stands up a **real asyncssh SSH server** on
`127.0.0.1` (password + public-key auth, SFTP subsystem, direct-tcpip for forwards/jumps),
drives the MCP server over a **real stdio MCP client**, and proves session survival across
daemon/client restarts. ~125 checks, zero keychain operations.

## Design credits / prior art

Deliberately built on top of patterns proven by these projects (studied during design):

| Project | What we borrowed |
|---|---|
| [slepp/ssh-mcp](https://github.com/slepp/ssh-mcp) | permission-gateable forward tool; idempotent named sessions; observable lifecycle fields |
| [jaenster/remote-shell-mcp](https://github.com/jaenster/remote-shell-mcp) | resident-daemon architecture (sessions outlive the MCP client); token-authenticated local bridge |
| [xunuo2345/ssh-mcp-toolkit](https://github.com/xunuo2345/ssh-mcp-toolkit) | ProxyJump chain + SFTP over the same tunnel; async exec with polling |
| [mcp-remote-ssh](https://pypi.org/project/mcp-remote-ssh/) | secret-safe injection + auto output redaction; structured exit codes |
| [d3v1an/ssh-mcp](https://github.com/d3v1an/ssh-mcp) | host-fingerprint pinning; `confirm` gating + undo/audit thinking |
| [xcdd/Agent-SSH-MCP](https://github.com/xcdd/Agent-SSH-MCP) | dual start/exit markers over tmux (we use a nonce marker without tmux deps) |
| [bhayanak/ssh-server-mcp](https://github.com/bhayanak/ssh-server-mcp) | background-job polling; strict host-key modes |
| [mvplab-ai/agent-vault](https://github.com/mvplab-ai/agent-vault) | reference-by-name vault; output scrubbing incl. encodings; append-only name-only audit |
| [DatanoiseTV/secrets-mcp](https://github.com/DatanoiseTV/secrets-mcp) | native hidden-input credential dialogs; guarded vault paths |
| [wundervault](https://github.com/wundervault/wundervault-mcp) | keys-stored-not-on-disk for SSH; burn-after-reading |
| [brewtools/ssh skill](https://github.com/kochetkov-ma/claude-brewcode) (brewcode) | READ/CREATE/MODIFY/SERVICE/DELETE/PRIVILEGE risk tiers + confirm gates |
| [Eriemon/remote-ssh](https://github.com/Eriemon/remote-ssh) | conservative reviewed operation patterns; redacted output by default |
| [badseal/ssh-skill](https://github.com/badseal/ssh-skill) | "local is out of scope" skill boundary; trigger-word discipline |
| [MCP SEP-2779](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/2779) | reference-based credential resolution at the client boundary |
| [MCP spec 2026-07-28](https://modelcontextprotocol.io/specification) | tool annotations (`readOnlyHint`/`destructiveHint`), elicitation rules for sensitive input |

## License

MIT — see [LICENSE](LICENSE).

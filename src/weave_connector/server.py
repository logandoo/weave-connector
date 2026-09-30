from __future__ import annotations

import asyncio
import base64
import functools
import os
import sys

from mcp.server.fastmcp import FastMCP

from .config import load_settings, resolve_config_path, scrub_text

mcp = FastMCP("weave-connector")

_backend = None
_backend_mode = None


async def get_backend():
    """Local Manager, or a daemon proxy when WEAVE_CONNECTOR_DAEMON != off
    (sessions then survive MCP client restarts)."""
    global _backend, _backend_mode
    mode = os.environ.get("WEAVE_CONNECTOR_DAEMON", "on").lower()
    if _backend is None or _backend_mode != mode:
        if mode == "off":
            _backend = _make_local()
        else:
            try:
                from .daemon import RemoteManager, ensure_daemon
                _backend = RemoteManager(await ensure_daemon())
            except Exception:
                _backend = _make_local()
        _backend_mode = mode
    return _backend


def _make_local():
    from .session import Manager
    path = resolve_config_path()
    mgr = Manager(load_settings(path), config_path=path, config_found=os.path.exists(path))
    mgr.reload_if_changed()
    return mgr


def safe(fn):
    """Uniform tool error shape: {"error": ...} instead of MCP protocol exceptions."""
    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        try:
            return await fn(*args, **kwargs)
        except Exception as exc:
            return {"error": scrub_text(f"{type(exc).__name__}: {exc}")}
    return wrapper


async def _call(method: str, **kwargs):
    """Uniform dispatch: local Manager methods and daemon RPC share a surface."""
    global _backend
    b = await get_backend()
    if type(b).__name__ == "Manager":
        b.reload_if_changed()   # local mode hot-reload (daemon reloads per request)
    try:
        result = getattr(b, method)(**kwargs)
        return await result if asyncio.iscoroutine(result) else result
    except ConnectionError:
        # daemon died mid-flight: drop the cached backend, respawn, retry once
        _backend = None
        b = await get_backend()
        result = getattr(b, method)(**kwargs)
        return await result if asyncio.iscoroutine(result) else result


@mcp.tool(annotations={"readOnlyHint": True})
@safe
async def ssh_list_profiles() -> dict:
    """List configured SSH host profiles from config.toml. Secrets are never returned."""
    return await _call("list_profiles_info")


@mcp.tool()
@safe
async def ssh_connect(profile: str = "") -> dict:
    """Open (or reuse) a persistent SSH connection for a profile. Channel stays open across tool calls."""
    return await _call("connect", name=profile or None)


@mcp.tool(annotations={"destructiveHint": True})
@safe
async def ssh_disconnect(profile: str = "") -> dict:
    """Close the persistent connection for a profile and all of its shell sessions."""
    return await _call("disconnect", name=profile or None)


@mcp.tool()
@safe
async def ssh_shell_open(profile: str = "", cwd: str = "", env: dict | None = None,
                         cols: int = 120, rows: int = 40, term: str = "xterm-256color",
                         name: str = "", record: bool = False) -> dict:
    """Open a persistent interactive shell (PTY) on a profile.

    State (cwd, exports, running programs) persists across all later tool calls
    on the returned session_id — and, via the resident daemon, across MCP client
    restarts. name= labels the session for idempotent reuse; record=true keeps a
    scrubbed transcript (see ssh_shell_transcript)."""
    return await _call("open_shell", name=profile or None, cwd=cwd or None, env=env,
                       cols=cols, rows=rows, term=term, session_name=name, record=record)


@mcp.tool(annotations={"destructiveHint": True})
@safe
async def ssh_shell_exec(session_id: str, command: str, timeout_ms: int = 30000,
                         max_chars: int = 12000, confirm: bool = False) -> dict:
    """Run a single-line command in a persistent shell and wait for completion (exit code returned).

    On timeout the command keeps running: poll ssh_shell_read or finish with
    ssh_shell_await. Multi-line commands and trailing &, |, \\ are rejected —
    use ssh_shell_write for those and for interactive/TUI input.
    Commands classified MODIFY/SERVICE/DELETE/PRIVILEGE are refused unless
    confirm=True (ask the user first; blocked/confirmed runs are audited)."""
    return await _call("session_exec", session_id=session_id, command=command,
                       timeout_ms=timeout_ms, max_chars=max_chars, confirm=confirm)


@mcp.tool()
@safe
async def ssh_shell_await(session_id: str, timeout_ms: int = 30000,
                          max_chars: int = 12000) -> dict:
    """Wait for a previously timed-out ssh_shell_exec to finish; returns its exit code."""
    return await _call("session_await", session_id=session_id,
                       timeout_ms=timeout_ms, max_chars=max_chars)


@mcp.tool(annotations={"destructiveHint": True})
@safe
async def ssh_shell_reset(session_id: str, timeout_ms: int = 8000) -> dict:
    """Recover a wedged session: sends Ctrl-C and resyncs the completion protocol.

    Use when an exec never completes or the shell seems stuck. Fails cleanly if
    the shell is inside a TUI (drive it with ssh_shell_write or close it)."""
    return await _call("session_reset", session_id=session_id, timeout_ms=timeout_ms)


@mcp.tool(annotations={"destructiveHint": True})
@safe
async def ssh_shell_write(session_id: str, data: str = "", data_base64: str = "") -> dict:
    """Write raw input to a persistent shell without waiting (TUI keys, prompts, Ctrl-letters).

    data_base64 wins when both are given; use it for exact bytes/control characters."""
    raw = base64.b64decode(data_base64, validate=True) if data_base64 else data.encode()
    r = await _call("session_write", session_id=session_id, data=raw)
    return {**r, "session_id": session_id}


@mcp.tool(annotations={"readOnlyHint": True})
@safe
async def ssh_shell_read(session_id: str, cursor: int = 0, wait_ms: int = 0,
                         max_bytes: int = 12000) -> dict:
    """Incremental read of a shell's output stream from a cursor (0 = replay retained buffer).

    wait_ms long-polls for new output. Pass the returned cursor into the next call."""
    return await _call("session_read", session_id=session_id, cursor=cursor,
                       wait_ms=wait_ms, max_bytes=max_bytes)


@mcp.tool(annotations={"destructiveHint": True})
@safe
async def ssh_shell_signal(session_id: str, signal: str) -> dict:
    """Send a control signal to a shell: interrupt (Ctrl-C), eof (Ctrl-D), suspend (Ctrl-Z),
    quit (Ctrl-\\), terminate, kill (last two are best-effort channel signals)."""
    return await _call("session_signal", session_id=session_id, signal=signal)


@mcp.tool()
@safe
async def ssh_shell_resize(session_id: str, cols: int, rows: int) -> dict:
    """Resize a shell's PTY (affects wrapping and full-screen apps)."""
    return await _call("session_resize", session_id=session_id, cols=cols, rows=rows)


@mcp.tool(annotations={"readOnlyHint": True})
@safe
async def ssh_shell_list() -> dict:
    """List all persistent shell sessions with state, idle time, and cursor position."""
    return await _call("session_list")


@mcp.tool(annotations={"readOnlyHint": True})
@safe
async def ssh_shell_transcript(session_id: str, max_bytes: int = 65536) -> dict:
    """Return the scrubbed I/O transcript of a session opened with record=true."""
    return await _call("session_transcript", session_id=session_id, max_bytes=max_bytes)


@mcp.tool(annotations={"destructiveHint": True})
@safe
async def ssh_shell_close(session_id: str) -> dict:
    """Close one persistent shell session and its remote channel (connection stays up)."""
    return await _call("session_close", session_id=session_id)


@mcp.tool(annotations={"destructiveHint": True})
@safe
async def ssh_forward_open(profile: str = "", local_port: int = 0, remote_host: str = "",
                           remote_port: int = 0, local_host: str = "127.0.0.1",
                           confirm: bool = False) -> dict:
    """Open a local port forward (-L) through the profile's SSH connection.
    Separate tool so hosts can grant shell access without tunneling.
    local_port=0 picks a free port (returned as local_port).
    Non-loopback binds require confirm=True."""
    return await _call("forward_open", name=profile or None, local_port=local_port,
                       remote_host=remote_host, remote_port=remote_port,
                       local_host=local_host, confirm=confirm)


@mcp.tool(annotations={"readOnlyHint": True})
@safe
async def ssh_forward_list() -> dict:
    """List active port forwards."""
    return await _call("forward_list")


@mcp.tool()
@safe
async def ssh_forward_close(forward_id: str) -> dict:
    """Close a port forward."""
    return await _call("forward_close", forward_id=forward_id)


@mcp.tool(annotations={"readOnlyHint": True})
@safe
async def ssh_sftp_list(profile: str = "", remote_path: str = ".") -> dict:
    """List a remote directory via SFTP (clean metadata, no shell quoting pitfalls)."""
    return await _call("sftp_list", name=profile or None, remote_path=remote_path)


@mcp.tool(annotations={"readOnlyHint": True})
@safe
async def ssh_sftp_read(profile: str = "", remote_path: str = "",
                        max_bytes: int = 65536) -> dict:
    """Read a remote file via SFTP (clean bytes, no shell)."""
    return await _call("sftp_read", name=profile or None, remote_path=remote_path,
                       max_bytes=max_bytes)


@mcp.tool(annotations={"destructiveHint": True})
@safe
async def ssh_sftp_write(profile: str = "", remote_path: str = "", content: str = "",
                         confirm: bool = False) -> dict:
    """Create/overwrite a remote file via SFTP — no shell quoting pitfalls.
    MODIFY-class: refused unless confirm=True (ask the user first)."""
    return await _call("sftp_write", name=profile or None, remote_path=remote_path,
                       content=content, confirm=confirm)


@mcp.tool(annotations={"destructiveHint": True})
@safe
async def ssh_sftp_upload(profile: str = "", local_path: str = "", remote_path: str = "",
                          confirm: bool = False) -> dict:
    """Upload a local file to the remote host via SFTP. MODIFY-class: confirm required."""
    return await _call("sftp_upload", name=profile or None, local_path=local_path,
                       remote_path=remote_path, confirm=confirm)


@mcp.tool(annotations={"destructiveHint": True})
@safe
async def ssh_sftp_download(profile: str = "", remote_path: str = "", local_path: str = "",
                            confirm: bool = False, overwrite: bool = False) -> dict:
    """Download a remote file to a local path via SFTP. MODIFY-class: confirm required.
    Refuses to clobber an existing local file unless overwrite=True."""
    return await _call("sftp_download", name=profile or None, remote_path=remote_path,
                       local_path=local_path, confirm=confirm, overwrite=overwrite)


@mcp.tool(annotations={"destructiveHint": True})
@safe
async def ssh_credential_enroll(profile: str = "", source: str = "dialog",
                                kind: str = "password", confirm: bool = False) -> dict:
    """Store a profile credential into the LOCAL VAULT (0600 file) WITHOUT the
    value passing through tool arguments or model context. Never the keychain.
    kind='password': source='dialog', 'env:WEAVE_ENROLL_*', or 'file:<path>'.
    kind='key': source='file:<path to PEM>'.
    After enrolling use password_ref / key_ref = "vault:<profile>"."""
    return await _call("enroll", profile_name=profile or None, source=source,
                       kind=kind, confirm=confirm)


@mcp.tool(annotations={"readOnlyHint": True})
@safe
async def ssh_status() -> dict:
    """Overview: config state, live connections, sessions, profiles (no secrets)."""
    return await _call("status")


@mcp.tool(annotations={"readOnlyHint": True})
@safe
async def ssh_daemon_status() -> dict:
    """Resident daemon status (sessions survive MCP client restarts when daemon is on)."""
    mode = os.environ.get("WEAVE_CONNECTOR_DAEMON", "on").lower()
    if mode == "off":
        return {"daemon": False, "mode": "in-process"}
    b = await get_backend()
    if hasattr(b, "_client"):
        return await _call("daemon_status")
    return {"daemon": False, "mode": "in-process"}


@mcp.tool(annotations={"destructiveHint": True})
@safe
async def ssh_daemon_stop() -> dict:
    """Stop the resident daemon (all sessions and connections are closed)."""
    b = await get_backend()
    if not hasattr(b, "_client"):
        return {"stopped": False, "note": "no daemon (in-process mode)"}
    return await _call("daemon_stop")


def main():
    mcp.run()


if __name__ == "__main__":
    sys.exit(main())

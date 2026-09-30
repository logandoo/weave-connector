from __future__ import annotations

import asyncio
import os
import re
import secrets
import shlex
import subprocess
import time
import uuid
from contextlib import suppress

import asyncssh

from .config import (Profile, Settings, load_settings, register_secret, scrub_text,
                     audit_event, SecretResolver, state_dir, validate_enroll_source)
from .risk import classify, CONFIRM_LEVELS

ANSI_RE = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07]*(?:\x07|\x1b\\)|\x1b[@-_]|\r")
ANY_MARKER_LINE_RE = re.compile(r"__WC_(?:EXIT|RESET)_")
ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

SIGNAL_BYTES = {
    "interrupt": b"\x03",
    "eof": b"\x04",
    "suspend": b"\x1a",
    "quit": b"\x1c",
}

MAX_SESSIONS = 32
REJECT_TAIL = ("\\", "&", "|", "&&", "||")


def strip_ansi(data: bytes) -> bytes:
    return ANSI_RE.sub(b"", data)


def _marker_re(nonce: str) -> re.Pattern[bytes]:
    return re.compile(rb"\r?\n__WC_EXIT_" + nonce.encode() + rb"_(\d+)__\r?\n?")


class ShellSession:
    def __init__(self, profile: Profile, conn: asyncssh.SSHClientConnection, proc,
                 cols: int, rows: int, max_buffer: int, name: str = ""):
        self.id = uuid.uuid4().hex[:12]
        self.name = name
        self.profile = profile
        self.conn = conn
        self.proc = proc
        self.cols = cols
        self.rows = rows
        self.max_buffer = max_buffer
        self.buffer = bytearray()
        self.base = 0          # absolute offset of buffer[0]
        self.total = 0         # absolute offset of next byte to append
        self.event = asyncio.Event()  # generation event: cleared before check, set on append
        self.alive = True
        self.pending = False   # an exec marker is outstanding
        self._pending_start = 0
        self._pending_re: re.Pattern[bytes] | None = None
        self.created_at = time.time()
        self.last_active = time.time()
        self.record = False
        self.transcript: list[tuple[str, bytes]] = []
        self._reader = asyncio.create_task(self._pump())

    async def _pump(self):
        try:
            while True:
                data = await self.proc.stdout.read(65536)
                if not data:
                    break
                self._append(data if isinstance(data, bytes) else data.encode())
        except Exception as exc:  # connection dropped, channel error, ...
            self._append(f"\r\n[weave-connector] reader ended: {exc}\r\n".encode())
        finally:
            self.alive = False
            self.event.set()

    def _log_io(self, direction: str, data: bytes):
        if self.record:
            # scrub at record time — raw secrets never sit in daemon memory
            safe_data = scrub_text(data.decode(errors="replace")).encode()
            self.transcript.append((direction, safe_data[:4096]))
            total = sum(len(d) for _dir, d in self.transcript)
            while self.transcript and (len(self.transcript) > 5000 or total > 4 * 1024 * 1024):
                _d, dropped = self.transcript.pop(0)
                total -= len(dropped)

    def _append(self, data: bytes):
        self._log_io("<", data)
        self.buffer.extend(data)
        self.total += len(data)
        if len(self.buffer) > self.max_buffer:
            drop = len(self.buffer) - self.max_buffer
            del self.buffer[:drop]
            self.base += drop
        self.last_active = time.time()
        self.event.set()

    def _touch(self):
        self.last_active = time.time()

    def _slice(self, start: int, end: int | None = None) -> bytes:
        end = self.total if end is None else min(end, self.total)
        start = max(start, self.base)
        if end <= start:
            return b""
        return bytes(self.buffer[start - self.base:end - self.base])

    def _find_marker(self, start: int):
        if self._pending_re is None:
            return None
        data = self._slice(start)
        matches = list(self._pending_re.finditer(data))
        if not matches:
            return None
        m = matches[-1]  # last occurrence: the real marker prints after all output
        return start + m.start(), start + m.end(), int(m.group(1))

    async def _wait_marker(self, start: int, timeout_ms: int):
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(timeout_ms, 0) / 1000
        while True:
            found = self._find_marker(start)
            if found:
                return found
            if not self.alive:
                return None
            remaining = deadline - loop.time()
            if remaining <= 0:
                return None
            self.event.clear()
            # re-check after clear so an append between check and wait can't be lost
            found = self._find_marker(start)
            if found:
                return found
            try:
                await asyncio.wait_for(self.event.wait(), remaining)
            except asyncio.TimeoutError:
                pass

    @staticmethod
    def _validate_command(command: str) -> str | None:
        if any(ord(c) < 0x20 and c != "\t" for c in command):
            return ("command contains control characters (CR/newline/NUL etc.); "
                    "send one clean single line, or drive multi-step input via ssh_shell_write")
        stripped = command.rstrip()
        if "\n" in stripped:
            return ("multi-line commands are not supported by ssh_shell_exec "
                    "(marker would be unreliable); send lines via ssh_shell_write instead")
        tail = stripped.rstrip()
        for bad in REJECT_TAIL:
            if tail.endswith(bad):
                return (f"command ends with {bad!r}; the completion marker cannot be "
                        f"attached reliably — background/chain it explicitly or use ssh_shell_write")
        return None

    async def exec(self, command: str, timeout_ms: int, max_chars: int,
                   confirm: bool = False, _internal: bool = False) -> dict:
        self._touch()
        level = classify(command)
        audit_cmd = scrub_text(command)[:200]
        if not _internal and level in CONFIRM_LEVELS and not confirm:
            audit_event({"event": "exec_blocked", "risk": level, "command": audit_cmd,
                         "profile": self.profile.name, "host": self.profile.host})
            return {"error": f"command classified {level}: needs confirm=True to run "
                             f"(ask the user first, then re-run with confirm)",
                    "requires_confirm": True, "risk_level": level, "completed": False}
        if not self.alive:
            return {"error": "session is not alive", "completed": False, "alive": False}
        if self.pending:
            return {"error": "a previous ssh_shell_exec is still running; use ssh_shell_await, "
                             "ssh_shell_signal, or ssh_shell_reset",
                    "completed": False}
        problem = self._validate_command(command)
        if problem:
            return {"error": problem, "completed": False}
        nonce = secrets.token_hex(4)
        self.pending = True
        self._pending_re = _marker_re(nonce)
        start = self.total
        self._pending_start = start
        # single-line form: a queued second line would be flushed from the tty
        # input queue by Ctrl-C (VINTR), losing the marker; `; printf` on the
        # same line survives because bash continues the list after SIGINT.
        if not _internal and level in CONFIRM_LEVELS:
            audit_event({"event": "exec_confirmed", "risk": level, "command": audit_cmd,
                         "profile": self.profile.name, "host": self.profile.host})
        payload = (command.rstrip("\n")
                   + f"; printf '\\n__WC_EXIT_{nonce}_%s__\\n' \"$?\"\n")
        self._log_io(">", payload.encode())
        self.proc.stdin.write(payload.encode())
        found = await self._wait_marker(start, timeout_ms)
        return self._exec_result(found, start, timeout_ms, max_chars)

    def _exec_result(self, found, start: int, timeout_ms: int, max_chars: int) -> dict:
        if not self.alive and found is None:
            self.pending = False
            self._pending_re = None
            return {"completed": False, "alive": False,
                    "error": "session ended before the command completed",
                    "output": self._clean(self._slice(start), max_chars)[0],
                    "cursor": self.total}
        if found is None:
            return {
                "completed": False,
                "timeout": True,
                "alive": self.alive,
                "cursor": self.total,
                "output": self._clean(self._slice(start), max_chars)[0],
                "hint": "still running — poll ssh_shell_read(cursor) or ssh_shell_await(session_id)",
            }
        self.pending = False
        self._pending_re = None
        m_start, _m_end, exit_code = found
        output, truncated = self._clean(self._slice(start, m_start), max_chars)
        return {
            "completed": True,
            "exit_code": exit_code,
            "output": output,
            "truncated": truncated,
            "cursor": self.total,
        }

    async def await_pending(self, timeout_ms: int, max_chars: int) -> dict:
        self._touch()
        if not self.pending or self._pending_re is None:
            return {"completed": False, "error": "no pending ssh_shell_exec on this session"}
        start = self._pending_start
        found = await self._wait_marker(start, timeout_ms)
        return self._exec_result(found, start, timeout_ms, max_chars)

    async def reset(self, timeout_ms: int = 8000) -> dict:
        """Recover a wedged session: Ctrl-C, then a fresh marker line to resync."""
        if not self.alive:
            return {"error": "session is not alive", "alive": False}
        self.write_raw(SIGNAL_BYTES["interrupt"])
        await asyncio.sleep(0.3)
        self.pending = False
        self._pending_re = None
        nonce = secrets.token_hex(4)
        marker_re = re.compile(rb"\r?\n__WC_RESET_" + nonce.encode() + rb"__\r?\n?")
        start = self.total
        self.proc.stdin.write(f"printf '\\n__WC_RESET_{nonce}__\\n'\n".encode())
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_ms / 1000
        while True:
            if marker_re.search(self._slice(start)):
                return {"reset": True, "session_id": self.id, "alive": True,
                        "cursor": self.total}
            if not self.alive:
                return {"reset": False, "alive": False,
                        "error": "session ended during reset"}
            remaining = deadline - loop.time()
            if remaining <= 0:
                return {"reset": False, "alive": True, "cursor": self.total,
                        "error": "shell did not answer after interrupt; it may be stuck "
                                 "in a TUI — send keys via ssh_shell_write or close it"}
            self.event.clear()
            if marker_re.search(self._slice(start)):
                continue
            try:
                await asyncio.wait_for(self.event.wait(), remaining)
            except asyncio.TimeoutError:
                pass

    @staticmethod
    def _clean(data: bytes, max_chars: int) -> tuple[str, bool]:
        text = strip_ansi(data).decode(errors="replace")
        text = scrub_text(text)
        lines = [ln for ln in text.split("\n") if not ANY_MARKER_LINE_RE.search(ln)]
        # drop leading blank lines (marker printf emits one) but keep interior formatting
        while lines and lines[0].strip() == "":
            lines.pop(0)
        text = "\n".join(lines)
        max_chars = max(max_chars, 200)
        truncated = len(text) > max_chars
        if truncated:
            text = text[-max_chars:]
        return text, truncated

    def write_raw(self, data: bytes) -> dict:
        if not self.alive:
            return {"error": "session is not alive", "alive": False}
        self.proc.stdin.write(data)
        self._log_io(">", data)
        self._touch()
        audit_event({"event": "raw_write", "bytes": len(data),
                     "preview": scrub_text(data.decode(errors="replace"))[:120],
                     "profile": self.profile.name, "host": self.profile.host})
        return {"written_bytes": len(data), "alive": True}

    async def read(self, cursor: int, wait_ms: int, max_bytes: int) -> dict:
        self._touch()
        cursor = max(cursor, 0)
        data_loss = cursor < self.base
        if cursor < self.base:
            cursor = self.base
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(wait_ms, 0) / 1000
        while self.total <= cursor and self.alive and wait_ms > 0:
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            self.event.clear()
            if self.total > cursor:
                break
            try:
                await asyncio.wait_for(self.event.wait(), remaining)
            except asyncio.TimeoutError:
                break
        data = self._slice(cursor, min(self.total, cursor + max(max_bytes, 1)))
        return {
            "output": scrub_text(strip_ansi(data).decode(errors="replace")),
            "cursor": cursor + len(data),
            "data_loss": data_loss,
            "alive": self.alive,
            "pending_exec": self.pending,
        }

    async def signal(self, name: str) -> dict:
        if name in SIGNAL_BYTES:
            r = self.write_raw(SIGNAL_BYTES[name])
            if "error" in r:
                return r
            return {"sent": name, "alive": self.alive}
        if name in ("terminate", "kill"):
            try:
                if name == "terminate":
                    self.proc.terminate()
                else:
                    self.proc.kill()
                return {"sent": name, "alive": self.alive,
                        "note": "best-effort: remote sshd may ignore session signals"}
            except Exception as exc:
                return {"error": f"signal {name} failed: {exc}", "alive": self.alive}
        return {"error": f"unknown signal {name!r}", "known": sorted(SIGNAL_BYTES) + ["terminate", "kill"]}

    def resize(self, cols: int, rows: int) -> dict:
        cols = min(max(int(cols), 20), 500)
        rows = min(max(int(rows), 5), 200)
        try:
            self.proc.change_terminal_size(cols, rows)
        except Exception as exc:
            return {"error": f"resize failed: {exc}", "alive": self.alive}
        self.cols, self.rows = cols, rows
        return {"size": f"{cols}x{rows}", "alive": self.alive}

    async def close(self):
        self.alive = False
        try:
            self.proc.close()
            with suppress(Exception):
                await asyncio.wait_for(self.proc.wait_closed(), 3)
        except Exception:
            pass
        if self._reader:
            self._reader.cancel()
            with suppress(asyncio.CancelledError):
                await self._reader
        self.event.set()

    def info(self) -> dict:
        return {
            "session_id": self.id,
            "name": self.name,
            "profile": self.profile.name,
            "alive": self.alive,
            "pending_exec": self.pending,
            "size": f"{self.cols}x{self.rows}",
            "cursor": self.total,
            "idle_sec": int(time.time() - self.last_active),
            "age_sec": int(time.time() - self.created_at),
        }


class Manager:
    def __init__(self, settings: Settings, config_path: str = "", config_found: bool = True):
        self.settings = settings
        self.config_path = config_path
        self.config_found = config_found
        self._config_mtime = self._mtime()
        self.connections: dict[str, asyncssh.SSHClientConnection] = {}
        self._conn_ident: dict[str, tuple] = {}
        self.sessions: dict[str, ShellSession] = {}
        self.forwards: dict[str, dict] = {}
        self._name_reservations: set[str] = set()
        self._locks: dict[str, asyncio.Lock] = {}
        self._reaper: asyncio.Task | None = None

    def _mtime(self):
        try:
            st = os.stat(self.config_path)
            return (st.st_mtime, st.st_mode & 0o777)
        except OSError:
            return (0.0, 0)

    def reload_if_changed(self) -> bool:
        """Hot-reload config.toml when the file changed (content or permissions);
        live sessions/connections keep their already-resolved Profile objects."""
        mtime = self._mtime()
        if mtime == self._config_mtime:
            return False
        self._config_mtime = mtime
        self.settings = load_settings(self.config_path)
        self.config_found = mtime != (0.0, 0)
        return True

    def start_reaper(self):
        if self.settings.idle_timeout_sec > 0 and self._reaper is None:
            self._reaper = asyncio.create_task(self._reap())

    async def _reap(self):
        while True:
            await asyncio.sleep(30)
            idle = self.settings.idle_timeout_sec
            for sid, s in list(self.sessions.items()):
                if time.time() - s.last_active > idle:
                    with suppress(Exception):
                        await self.close_session(sid)

    def get_profile(self, name: str | None) -> Profile:
        name = name or self.settings.default_profile
        if not name or name not in self.settings.profiles:
            hint = "" if self.config_found else (
                f" (config file not found at {self.config_path!r} — set WEAVE_CONNECTOR_CONFIG)")
            raise ValueError(
                f"unknown profile {name!r}; known: {sorted(self.settings.profiles)}{hint}")
        return self.settings.profiles[name]

    def _validate_jump_chain(self, p: Profile):
        seen = {p.name}
        cur = p
        depth = 0
        while cur.jump:
            depth += 1
            if depth > 8:
                raise ValueError(f"jump chain too deep starting at {p.name!r}")
            if cur.jump in seen:
                raise ValueError(f"jump cycle detected: {' -> '.join(sorted(seen))} -> {cur.jump!r}")
            seen.add(cur.jump)
            cur = self.get_profile(cur.jump)

    async def connect(self, name: str | None) -> dict:
        self.start_reaper()
        p = self.get_profile(name)
        if p.jump:
            self._validate_jump_chain(p)
        lock = self._locks.setdefault(p.name, asyncio.Lock())
        ident = (p.host, p.port, p.username, p.key, p.password_ref,
                 p.password is not None, p.host_fingerprint, p.accept_unknown_host,
                 p.jump)
        async with lock:
            conn = self.connections.get(p.name)
            if conn is not None and (conn.is_closed()
                                     or self._conn_ident.get(p.name) != ident):
                conn.close()
                conn = None
            if conn is None:
                client_keys = [p.key] if p.key else None
                if p.key_ref:
                    try:
                        pem = await asyncio.to_thread(SecretResolver().resolve, p.key_ref)
                    except ValueError:
                        audit_event({"event": "resolve_ref", "ref": p.key_ref,
                                     "profile": p.name, "host": p.host, "ok": False})
                        raise
                    register_secret(pem)
                    audit_event({"event": "resolve_ref", "ref": p.key_ref,
                                 "profile": p.name, "host": p.host, "ok": True})
                    client_keys = [asyncssh.import_private_key(pem)]
                pw = p.password
                if p.password_ref:
                    try:
                        # off-loop: keychain lookups can block (GUI prompt, 10s timeout)
                        pw = await asyncio.to_thread(SecretResolver().resolve, p.password_ref)
                    except ValueError:
                        audit_event({"event": "resolve_ref", "ref": p.password_ref,
                                     "profile": p.name, "host": p.host, "ok": False})
                        raise
                    audit_event({"event": "resolve_ref", "ref": p.password_ref,
                                 "profile": p.name, "host": p.host, "ok": True})
                if pw:
                    register_secret(pw)
                tunnel = None
                if p.jump:
                    await self.connect(p.jump)   # fail-closed on unknown profile
                    jconn = self.connections.get(self.get_profile(p.jump).name)
                    if jconn is None or jconn.is_closed():
                        raise ValueError(f"jump profile {p.jump!r} connection unavailable")
                    tunnel = jconn
                kwargs = dict(
                    host=p.host,
                    port=p.port,
                    tunnel=tunnel,
                    username=p.username or None,
                    password=pw,
                    client_keys=client_keys,
                    keepalive_interval=30,
                    keepalive_count_max=3,
                    login_timeout=15,
                )
                if p.host_fingerprint:
                    fp = p.host_fingerprint

                    import hmac as _hmac
                    norm = fp.strip()
                    if norm.lower().startswith("sha256:"):
                        norm = "SHA256:" + norm.split(":", 1)[1]

                    class _Pinned(asyncssh.SSHClient):
                        def validate_host_public_key(self, host, addr, port, key):
                            return _hmac.compare_digest(key.get_fingerprint(), norm)

                    # truthy EMPTY trust set: a plain {} is falsy and asyncssh
                    # would silently fall back to ~/.ssh/known_hosts, letting a
                    # pre-trusted key bypass the pin (review C1)
                    kwargs["known_hosts"] = asyncssh.import_known_hosts("")
                    kwargs["server_host_key_algs"] = "default"
                    kwargs["client_factory"] = _Pinned
                elif p.accept_unknown_host:
                    kwargs["known_hosts"] = None
                elif p.known_hosts:
                    kwargs["known_hosts"] = p.known_hosts
                conn = await asyncssh.connect(**kwargs)
                self.connections[p.name] = conn
                self._conn_ident[p.name] = ident
        return {
            "profile": p.name,
            "host": p.host,
            "port": p.port,
            "username": p.username,
            "sessions": [s.id for s in self.sessions.values() if s.profile.name == p.name],
        }

    async def disconnect(self, name: str | None) -> dict:
        p = self.get_profile(name)
        for sid, s in list(self.sessions.items()):
            if s.profile.name == p.name:
                await self.close_session(sid)
        for fid, f in list(self.forwards.items()):
            if f["profile"] == p.name:
                self.forwards.pop(fid, None)
                with suppress(Exception):
                    f["listener"].close()
        conn = self.connections.pop(p.name, None)
        if conn:
            conn.close()
            with suppress(Exception):
                await conn.wait_closed()
        return {"disconnected": p.name}

    async def open_shell(self, name: str | None, cwd: str | None, env: dict | None,
                         cols: int, rows: int, term: str, session_name: str = "",
                         record: bool = False) -> dict:
        for k in (env or {}):
            if not ENV_KEY_RE.match(k):
                raise ValueError(f"invalid env var name {k!r}")
        if session_name:
            matches = [s for s in self.sessions.values()
                       if s.name == session_name and s.alive]
            if matches:
                s = matches[0]
                if name:  # explicit profile must match the binding
                    requested_profile = self.get_profile(name).name
                    if s.profile.name != requested_profile:
                        raise ValueError(f"session name {session_name!r} is bound to "
                                         f"profile {s.profile.name!r}, not {requested_profile!r}")
                ignored = [k for k, v in (("cwd", cwd), ("env", env),
                                          ("cols", cols != 120), ("rows", rows != 40),
                                          ("term", term != "xterm-256color")) if v]
                return {"session_id": s.id, "name": s.name, "profile": s.profile.name,
                        "cursor": s.total, "size": f"{s.cols}x{s.rows}",
                        "reused": True, "ignored_params": ignored}
        await self.connect(name)
        p = self.get_profile(name)
        for dsid, ds in list(self.sessions.items()):
            if not ds.alive:
                self.sessions.pop(dsid, None)
                self._name_reservations.discard(ds.name)
        if len(self.sessions) >= MAX_SESSIONS:
            raise ValueError(f"session cap {MAX_SESSIONS} reached")
        if session_name:
            if session_name in self._name_reservations:
                raise ValueError(f"session name {session_name!r} is being created concurrently")
            self._name_reservations.add(session_name)
        try:
            return await self._open_shell_inner(p, cwd, env, cols, rows, term,
                                                session_name, record)
        except Exception:
            self._name_reservations.discard(session_name)
            raise

    async def _open_shell_inner(self, p, cwd, env, cols, rows, term,
                                session_name: str, record: bool) -> dict:
        conn = self.connections[p.name]
        proc = await conn.create_process(
            term_type=term, term_size=(cols, rows), encoding=None)
        s = ShellSession(p, conn, proc, cols, rows, self.settings.max_buffer_bytes,
                         name=session_name)
        s.record = record
        self.sessions[s.id] = s
        self._persist_session_spec(s, cwd, env)
        init = ["export HISTFILE=/dev/null", "set +o history"]
        if cwd:
            init.append(f"cd {shlex.quote(cwd)}")
        for k, v in (env or {}).items():
            init.append(f"export {k}={shlex.quote(str(v))}")
        result = await s.exec("; ".join(init), timeout_ms=15000, max_chars=4000,
                               _internal=True)
        # hide bootstrap noise from the cursor stream
        s.buffer.clear()
        s.base = s.total
        if not result.get("completed"):
            await self.close_session(s.id)
            raise ValueError("shell did not become ready "
                             "(host unreachable, slow init, or non-POSIX shell)")
        return {"session_id": s.id, "name": s.name, "profile": p.name, "cursor": s.total,
                "size": f"{cols}x{rows}", "term": term}

    def _persist_session_spec(self, s: "ShellSession", cwd: str | None, env: dict | None):
        """sessions.json = recovery hints only (no secrets: env KEYS, not values).
        Best-effort: any failure is swallowed (corrupt file must never brick
        open_shell — review I2)."""
        import json as _json
        path = os.path.join(state_dir(), "sessions.json")
        try:
            data = {}
            if os.path.exists(path):
                try:
                    with open(path) as f:
                        data = _json.load(f)
                except ValueError:
                    data = {}  # corrupt file self-repairs on this write
            data[s.name or s.id] = {"session_id": s.id, "name": s.name,
                                    "profile": s.profile.name, "cwd": cwd,
                                    "env_keys": sorted((env or {}).keys()),
                                    "cols": s.cols, "rows": s.rows,
                                    "created_at": s.created_at}
            tmp = path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                os.write(fd, _json.dumps(data, indent=1).encode())
            finally:
                os.close(fd)
            os.replace(tmp, path)
        except Exception:
            pass

    async def forward_open(self, name: str | None, local_port: int, remote_host: str,
                           remote_port: int, local_host: str = "127.0.0.1",
                           confirm: bool = False) -> dict:
        if not remote_host or not (1 <= int(remote_port) <= 65535):
            return {"error": "remote_host and a valid remote_port (1-65535) are required"}
        if not (int(local_port) == 0 or 1 <= int(local_port) <= 65535):
            return {"error": "local_port must be 0 (auto) or 1-65535"}
        if local_host not in ("127.0.0.1", "localhost", "::1"):
            if not confirm:
                return {"error": f"binding {local_host!r} exposes the forward beyond "
                                 f"loopback — needs confirm=True", "requires_confirm": True,
                        "risk_level": "MODIFY"}
        if len(self.forwards) >= 16:
            return {"error": "forward cap (16) reached — close unused forwards"}
        await self.connect(name)
        p = self.get_profile(name)
        conn = self.connections[p.name]
        listener = await conn.forward_local_port(local_host, local_port,
                                                 remote_host, remote_port)
        fid = uuid.uuid4().hex[:8]
        bound_port = listener.get_port()
        self.forwards[fid] = {"forward_id": fid, "listener": listener,
                              "profile": p.name, "host": p.host,
                              "local": f"{local_host}:{bound_port}",
                              "remote": f"{remote_host}:{remote_port}"}
        audit_event({"event": "forward_open", "local": f"{local_host}:{bound_port}",
                     "remote": f"{remote_host}:{remote_port}",
                     "profile": p.name, "host": p.host})
        return {"forward_id": fid, "local_port": bound_port,
                "local_host": local_host, "remote": f"{remote_host}:{remote_port}"}

    def forward_list(self) -> dict:
        return {"forwards": [{"forward_id": f["forward_id"], "profile": f["profile"],
                              "local": f["local"], "remote": f["remote"]}
                             for f in self.forwards.values()]}

    async def forward_close(self, forward_id: str) -> dict:
        f = self.forwards.pop(forward_id, None)
        if f is None:
            return {"error": f"unknown forward_id {forward_id!r}",
                    "active": sorted(self.forwards)}
        try:
            f["listener"].close()
            await f["listener"].wait_closed()
        except Exception:
            pass
        audit_event({"event": "forward_close", "forward_id": forward_id,
                     "profile": f["profile"], "host": f["host"]})
        return {"closed": forward_id}

    async def enroll(self, profile_name: str, source: str = "dialog",
                     kind: str = "password", confirm: bool = False) -> dict:
        """Store a profile credential into the local vault (0600 file) — never
        the keychain — without the value ever entering tool arguments or model
        context."""
        if kind not in ("password", "key"):
            return {"error": f"kind must be 'password' or 'key', got {kind!r}"}
        from .config import validate_enroll_source
        p = self.get_profile(profile_name)
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", p.name):
            return {"error": "profile name contains characters unsafe for the "
                             "enrollment dialog; rename the profile"}
        source = validate_enroll_source(source, kind=kind)
        if kind == "key":
            if not confirm:
                audit_event({"event": "enroll_key_blocked", "profile": profile_name})
                return {"error": "key enrollment reads a local private key file: "
                                 "needs confirm=True (ask the user first)",
                        "requires_confirm": True, "risk_level": "MODIFY"}
            pem_path = os.path.expanduser(source[5:])
            try:
                with open(pem_path, "rb") as f:
                    value = f.read().decode()
                asyncssh.import_private_key(value)  # fail-closed on garbage
            except Exception as exc:
                return {"error": f"key enrollment failed ({type(exc).__name__})"}
            register_secret(value)
            err = await asyncio.to_thread(self._secret_store, p.name, value)
            audit_event({"event": "enroll_key", "profile": p.name, "ok": err is None})
            if err is not None:
                return {"error": err}
            return {"stored": True, "kind": "key", "profile": p.name,
                    "key_ref": f"vault:{p.name}"}
        if source == "dialog":
            # fixed literal script: NO interpolation of profile/config data
            # (review C1 — a quoted TOML key could otherwise inject AppleScript)
            script = ('display dialog "SSH password (stored in local vault)" '
                      'with hidden answer default answer "" '
                      'buttons {"OK"} default button "OK"')
            try:
                proc = await asyncio.create_subprocess_exec(
                    "osascript", "-e", script,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE)
                out, err = await asyncio.wait_for(proc.communicate(), timeout=120)
            except asyncio.TimeoutError:
                with suppress(Exception):
                    proc.kill()
                return {"error": "dialog timed out (unattended session?) — "
                                 "use source='env:WEAVE_ENROLL_*' instead"}
            except Exception as exc:
                return {"error": f"dialog failed ({type(exc).__name__}) — "
                                 f"no GUI available? use source='env:WEAVE_ENROLL_*'"}
            if proc.returncode != 0:
                errbytes = err or b""
                if b"User canceled" in errbytes or b"-128" in errbytes:
                    return {"error": "dialog cancelled by user"}
                return {"error": "dialog unavailable (no GUI session?) — "
                                 "use source='env:WEAVE_ENROLL_*'"}
            text = out.decode(errors="replace")
            marker = "text returned:"
            value = text.split(marker, 1)[1].rstrip("\n") if marker in text else ""
            if not value:
                return {"error": "dialog cancelled or empty"}
        elif source.startswith("file:"):
            if not confirm:
                audit_event({"event": "enroll_blocked", "profile": p.name,
                             "source_kind": "file"})
                return {"error": "file source reads a local file into the vault: "
                                 "needs confirm=True (ask the user first)",
                        "requires_confirm": True, "risk_level": "MODIFY"}
            fpath = os.path.expanduser(source[5:])
            try:
                with open(fpath) as f:
                    value = f.read().rstrip("\n")
            except OSError as exc:
                return {"error": f"file source failed ({type(exc).__name__})"}
            if not value:
                return {"error": "file source is empty — nothing stored"}
        else:
            value = os.environ.get(source[4:], "")
            if not value:
                return {"error": f"server env {source[4:]!r} is not set"}
        # register BEFORE any store attempt so a failing store can never echo
        # the value back through error text (review C2)
        register_secret(value)
        err = await asyncio.to_thread(self._secret_store, p.name, value)
        audit_event({"event": "enroll", "profile": p.name,
                     "source_kind": source.split(":", 1)[0],
                     "source_detail": source.split(":", 1)[1][:80] if ":" in source else "",
                     "ok": err is None})
        if err is not None:
            return {"error": err}
        return {"stored": True, "profile": p.name,
                "password_ref": f"vault:{p.name}"}

    @staticmethod
    def _secret_store(account: str, value: str):
        """Local vault file (0600) — never the login keychain (D-12, zero prompts)."""
        try:
            from .config import store as _store
            _store.vault_set(account, value)
            return None
        except Exception:
            return "vault store failed (state dir not writable?)"

    def get_session(self, sid: str) -> ShellSession:
        s = self.sessions.get(sid)
        if s is None:
            raise ValueError(f"unknown session_id {sid!r}; active: {sorted(self.sessions)}")
        return s

    async def close_session(self, sid: str) -> dict:
        s = self.sessions.pop(sid, None)
        if s is None:
            return {"closed": sid, "note": "already closed"}
        self._name_reservations.discard(s.name)
        await s.close()
        return {"closed": sid}

    async def _sftp(self, name: str | None):
        await self.connect(name)
        p = self.get_profile(name)
        return self.connections[p.name], p

    async def sftp_list(self, name: str | None, remote_path: str) -> dict:
        conn, p = await self._sftp(name)
        audit_event({"event": "sftp_list", "path": remote_path,
                     "profile": p.name, "host": p.host})
        async with conn.start_sftp_client() as sftp:
            entries = await sftp.readdir(remote_path)
        import stat as _stat
        return {"entries": [{"name": scrub_text(e.filename),
                             "size": e.attrs.size if e.attrs else None,
                             "is_dir": bool(e.attrs and e.attrs.permissions
                                            and _stat.S_ISDIR(e.attrs.permissions)),
                             "mode": e.attrs.permissions if e.attrs else None,
                             "mtime": e.attrs.mtime if e.attrs else None}
                            for e in entries if e.filename not in (".", "..")]}

    async def sftp_read(self, name: str | None, remote_path: str, max_bytes: int) -> dict:
        conn, p = await self._sftp(name)
        max_bytes = min(max(max_bytes, 1), 2 * 1024 * 1024)  # OOM + RPC line-budget guard
        audit_event({"event": "sftp_read", "path": remote_path,
                     "profile": p.name, "host": p.host})
        async with conn.start_sftp_client() as sftp:
            async with sftp.open(remote_path, "rb") as f:
                data = await f.read(max_bytes + 1)
        truncated = len(data) > max_bytes
        data = data[:max_bytes]
        return {"content": scrub_text(data.decode(errors="replace")),
                "bytes": len(data), "truncated": truncated}

    async def sftp_write(self, name: str | None, remote_path: str, content: str,
                         confirm: bool = False) -> dict:
        conn, p = await self._sftp(name)
        err = self._sftp_gate("sftp_write", remote_path, p, confirm)
        if err:
            return err
        async with conn.start_sftp_client() as sftp:
            async with sftp.open(remote_path, "wb") as f:
                await f.write(content.encode())
        audit_event({"event": "sftp_write", "path": remote_path, "confirmed": confirm,
                     "profile": p.name, "host": p.host})
        return {"written_bytes": len(content.encode()), "remote_path": remote_path}

    async def sftp_upload(self, name: str | None, local_path: str, remote_path: str,
                          confirm: bool = False) -> dict:
        conn, p = await self._sftp(name)
        err = self._sftp_gate("sftp_upload", remote_path, p, confirm)
        if err:
            return err
        size = os.path.getsize(local_path)
        async with conn.start_sftp_client() as sftp:
            await sftp.put(local_path, remote_path)
        audit_event({"event": "sftp_upload", "local": local_path, "remote": remote_path,
                     "confirmed": confirm, "profile": p.name, "host": p.host})
        return {"uploaded_bytes": size, "remote_path": remote_path}

    async def sftp_download(self, name: str | None, remote_path: str, local_path: str,
                            confirm: bool = False, overwrite: bool = False) -> dict:
        conn, p = await self._sftp(name)
        err = self._sftp_gate("sftp_download", remote_path, p, confirm)
        if err:
            return err
        if os.path.lexists(local_path) and not overwrite:
            audit_event({"event": "sftp_download_blocked", "local": local_path,
                         "reason": "exists", "profile": p.name, "host": p.host})
            return {"error": f"local_path {local_path!r} already exists; "
                             f"pass overwrite=True to replace it"}
        async with conn.start_sftp_client() as sftp:
            await sftp.get(remote_path, local_path)
        audit_event({"event": "sftp_download", "remote": remote_path, "local": local_path,
                     "confirmed": confirm, "profile": p.name, "host": p.host})
        return {"downloaded_bytes": os.path.getsize(local_path), "local_path": local_path}

    @staticmethod
    def _sftp_gate(op: str, path: str, p: Profile, confirm: bool):
        """SFTP mutations are MODIFY-class: confirm required, always audited."""
        if not confirm:
            audit_event({"event": f"{op}_blocked", "path": path,
                         "profile": p.name, "host": p.host})
            return {"error": f"{op} is a MODIFY-class mutation: needs confirm=True "
                             f"(ask the user first)", "requires_confirm": True,
                    "risk_level": "MODIFY", "path": path}
        audit_event({"event": f"{op}_confirmed", "path": path,
                     "profile": p.name, "host": p.host})
        return None

    # ---- flat session surface (single JSON-safe seam for daemon RPC) ----
    def list_profiles_info(self) -> dict:
        return {"profiles": [p.public_dict() for p in self.settings.profiles.values()],
                "default_profile": self.settings.default_profile,
                "config_path": self.config_path, "config_found": self.config_found}

    async def session_exec(self, session_id: str, command: str, timeout_ms: int = 30000,
                           max_chars: int = 12000, confirm: bool = False) -> dict:
        return await self.get_session(session_id).exec(command, timeout_ms, max_chars, confirm)

    async def session_await(self, session_id: str, timeout_ms: int = 30000,
                            max_chars: int = 12000) -> dict:
        return await self.get_session(session_id).await_pending(timeout_ms, max_chars)

    async def session_reset(self, session_id: str, timeout_ms: int = 8000) -> dict:
        return await self.get_session(session_id).reset(timeout_ms)

    def session_write(self, session_id: str, data: bytes) -> dict:
        return self.get_session(session_id).write_raw(data)

    async def session_read(self, session_id: str, cursor: int = 0, wait_ms: int = 0,
                           max_bytes: int = 12000) -> dict:
        return await self.get_session(session_id).read(cursor, wait_ms, max_bytes)

    async def session_signal(self, session_id: str, signal: str) -> dict:
        return await self.get_session(session_id).signal(signal)

    def session_resize(self, session_id: str, cols: int, rows: int) -> dict:
        r = self.get_session(session_id).resize(cols, rows)
        return {**r, "session_id": session_id}

    async def session_close(self, session_id: str) -> dict:
        return await self.close_session(session_id)

    def session_list(self) -> dict:
        return {"sessions": [s.info() for s in self.sessions.values()]}

    def session_transcript(self, session_id: str, max_bytes: int = 65536) -> dict:
        s = self.get_session(session_id)
        max_bytes = min(max(int(max_bytes), 256), 262144)
        raw = b"".join(d for _dir, d in s.transcript[-2000:])
        text = scrub_text(raw.decode(errors="replace"))
        truncated = len(text) > max_bytes
        return {"transcript": text[-max_bytes:], "truncated": truncated,
                "recorded": s.record}

    def status(self) -> dict:
        return {
            "config_path": self.config_path,
            "config_found": self.config_found,
            "warnings": list(self.settings.warnings),
            "connections": {n: {"closed": c.is_closed()} for n, c in self.connections.items()},
            "sessions": [s.info() for s in self.sessions.values()],
            "profiles": [p.public_dict() for p in self.settings.profiles.values()],
            "default_profile": self.settings.default_profile,
            "idle_timeout_sec": self.settings.idle_timeout_sec,
        }

    async def shutdown(self):
        for fid, f in list(self.forwards.items()):
            self.forwards.pop(fid, None)
            with suppress(Exception):
                f["listener"].close()
        if self._reaper:
            self._reaper.cancel()
        for sid in list(self.sessions):
            await self.close_session(sid)
        for conn in self.connections.values():
            conn.close()
            with suppress(Exception):
                await conn.wait_closed()

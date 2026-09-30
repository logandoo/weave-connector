"""Resident session daemon: owns SSH connections/sessions so they survive MCP
client restarts. The MCP stdio server becomes a thin client over a unix socket.

Protocol: one JSON object per line.
  request  {"id": N, "token": T, "method": M, "args": {...}}
  response {"id": N, "ok": true, "result": ...} | {"id": N, "ok": false, "error": ...}
Bytes travel as {"__bytes__": "<base64>"}.
"""
from __future__ import annotations

import asyncio
import base64
import hmac
import json
import os
import secrets
import stat
import sys
import time

from .config import load_settings, resolve_config_path, state_dir
from .session import Manager


def sock_path() -> str:
    return os.environ.get("WEAVE_CONNECTOR_DAEMON_SOCK") or os.path.join(state_dir(), "daemon.sock")


def token_path() -> str:
    return os.path.join(os.path.dirname(sock_path()), "daemon.token")


def _encode(v):
    if isinstance(v, bytes):
        return {"__bytes__": base64.b64encode(v).decode()}
    if isinstance(v, dict):
        return {k: _encode(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_encode(x) for x in v]
    return v


def _decode(v):
    if isinstance(v, dict):
        if "__bytes__" in v:
            return base64.b64decode(v["__bytes__"])
        return {k: _decode(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_decode(x) for x in v]
    return v


ALLOWED_METHODS = {
    "ping", "list_profiles_info", "connect", "disconnect",
    "open_shell", "session_exec", "session_await", "session_reset",
    "session_write", "session_read", "session_signal", "session_resize",
    "session_list", "session_close", "session_transcript",
    "forward_open", "forward_list", "forward_close",
    "sftp_list", "sftp_read", "sftp_write", "sftp_upload", "sftp_download",
    "enroll", "status", "daemon_status", "daemon_stop",
}


class Daemon:
    def __init__(self):
        path = resolve_config_path()
        self.manager = Manager(load_settings(path), config_path=path,
                               config_found=os.path.exists(path))
        self._token = self._load_or_create_token()
        self._server = None
        self._stopping = asyncio.Event()

    @staticmethod
    def _load_or_create_token() -> str:
        tp = token_path()
        os.makedirs(os.path.dirname(tp), exist_ok=True)
        try:
            os.chmod(os.path.dirname(tp), 0o700)
        except OSError:
            pass
        tok = secrets.token_hex(32)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(tp, flags, 0o600)
        except FileExistsError:
            fd = os.open(tp, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                return os.read(fd, 4096).decode().strip()
            finally:
                os.close(fd)
        try:
            os.write(fd, tok.encode())
        finally:
            os.close(fd)
        return tok

    async def handle(self, reader, writer):
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                try:
                    req = json.loads(line)
                except ValueError:
                    writer.write(json.dumps({"id": 0, "ok": False, "error": "bad json"}).encode() + b"\n")
                    await writer.drain()
                    continue
                rid = req.get("id", 0)
                if not hmac.compare_digest(str(req.get("token", "")), self._token):
                    writer.write(json.dumps({"id": rid, "ok": False, "error": "bad token"}).encode() + b"\n")
                    await writer.drain()
                    continue
                method = req.get("method", "")
                args = _decode(req.get("args", {}))
                if method not in ALLOWED_METHODS:
                    resp = {"id": rid, "ok": False, "error": f"method not allowed: {method}"}
                else:
                    self.manager.reload_if_changed()
                    try:
                        if method == "ping":
                            result = {"pong": True}
                        elif method == "daemon_status":
                            result = {"daemon": True, "pid": os.getpid(),
                                      "sessions": len(self.manager.sessions)}
                        elif method == "daemon_stop":
                            result = {"stopped": True}
                            writer.write(json.dumps({"id": rid, "ok": True, "result": _encode(result)}).encode() + b"\n")
                            await writer.drain()
                            self._stopping.set()
                            break
                        else:
                            fn = getattr(self.manager, method)
                            result = fn(**args)
                            if asyncio.iscoroutine(result):
                                result = await result
                        resp = {"id": rid, "ok": True, "result": _encode(result)}
                    except Exception as exc:
                        from .config import scrub_text
                        self.manager.reload_if_changed()
                        resp = {"id": rid, "ok": False, "error": scrub_text(str(exc))}
                writer.write(json.dumps(resp).encode() + b"\n")
                await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def run(self):
        sp = sock_path()
        os.makedirs(os.path.dirname(sp), exist_ok=True)
        import fcntl
        lock_fd = os.open(os.path.join(os.path.dirname(sp), "daemon.lock"),
                          os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(lock_fd)
            return  # another daemon already owns this state dir
        if os.path.exists(sp):
            os.unlink(sp)  # safe: we hold the single-instance lock
        self._server = await asyncio.start_unix_server(self.handle, sp, limit=16 * 1024 * 1024)
        try:
            os.chmod(sp, 0o600)
        except OSError:
            pass
        async with self._server:
            await self._stopping.wait()
        await self.manager.shutdown()
        os.close(lock_fd)
        for p in (sp,):
            try:
                os.unlink(p)
            except OSError:
                pass


class DaemonClient:
    """One connection per call: calls run concurrently across tool invocations
    (a shared stream would serialize — and could deadlock signal-behind-exec)."""

    def __init__(self, sock: str, token: str):
        self._sock = sock
        self._token = token

    async def call(self, method: str, **args):
        try:
            reader, writer = await asyncio.open_unix_connection(self._sock, limit=16 * 1024 * 1024)
        except (OSError, ConnectionError) as exc:
            raise ConnectionError(f"daemon unavailable: {exc}") from exc
        try:
            req = {"id": 1, "token": self._token, "method": method, "args": _encode(args)}
            writer.write(json.dumps(req).encode() + b"\n")
            await writer.drain()
            line = await asyncio.wait_for(reader.readline(), timeout=600)
            if not line:
                raise ConnectionError("daemon closed the connection")
            resp = json.loads(line)
        except (OSError, ConnectionError):
            raise
        except ValueError as exc:
            raise ConnectionError(f"daemon protocol error: {exc}") from exc
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        if not resp.get("ok"):
            raise ValueError(resp.get("error", "daemon error"))
        return _decode(resp.get("result"))

    async def close(self):
        pass


class RemoteManager:
    """Proxy with the same flat surface as Manager; every call is an RPC."""

    def __init__(self, client: DaemonClient):
        self._client = client

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)

        async def call(**kwargs):
            return await self._client.call(name, **kwargs)

        def sync_call(**kwargs):
            return self._client.call(name, **kwargs)

        return call


async def daemon_ping() -> bool:
    try:
        tok = _read_token()
        c = DaemonClient(sock_path(), tok)
        r = await asyncio.wait_for(c.call("ping"), timeout=3)
        await c.close()
        return bool(r.get("pong"))
    except Exception:
        return False


def _read_token() -> str:
    fd = os.open(token_path(), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        return os.read(fd, 4096).decode().strip()
    finally:
        os.close(fd)


async def ensure_daemon() -> DaemonClient:
    """Return a client to the resident daemon, auto-spawning one if absent.
    A flock on daemon.lock makes spawn single-instance."""
    sp = sock_path()
    if await daemon_ping():
        return DaemonClient(sp, _read_token())
    os.makedirs(os.path.dirname(sp), exist_ok=True)
    import fcntl
    lock_fd = os.open(os.path.join(os.path.dirname(sp), "daemon.lock"),
                      os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        can_spawn = True
    except OSError:
        can_spawn = False  # another client (or the daemon) is already on it
    if can_spawn:
        await asyncio.create_subprocess_exec(
            sys.executable, "-m", "weave_connector.daemon",
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            start_new_session=True)
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
    os.close(lock_fd)
    for _ in range(50):
        await asyncio.sleep(0.1)
        if await daemon_ping():
            return DaemonClient(sp, _read_token())
    raise RuntimeError(f"daemon did not start (sock={sp})")


def main():
    asyncio.run(Daemon().run())


if __name__ == "__main__":
    main()

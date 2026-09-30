"""Real SSH server for integration tests: asyncssh + local PTY + real bash + SFTP.

Not a mock: speaks the SSH protocol, authenticates by password, attaches each
shell session to a genuine pseudo-terminal running /bin/bash (so echo, Ctrl-C
SIGINT, window size behave like a real host), and serves the SFTP subsystem.
"""
from __future__ import annotations

import asyncio
import fcntl
import os
import pty
import struct
import subprocess
import termios

import asyncssh

HOST_KEY_FILE = os.path.join(os.path.dirname(__file__), "evidence", "test_host_key")
class TestSSHServer(asyncssh.SSHServer):
    def __init__(self, authorized_keys: str | None = None):
        self.authorized_keys = authorized_keys

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return ((username == "tester" and password == "secret")
                or (username == "kcuser" and password == "kc-e2e-password-XYZ123456789"))

    def public_key_auth_supported(self):
        return self.authorized_keys is not None

    def validate_public_key(self, username, key):
        if not self.authorized_keys:
            return False
        try:
            pub = asyncssh.read_public_key(self.authorized_keys)
        except Exception:
            return False
        return key.get_fingerprint() == pub.get_fingerprint()

    def connection_requested(self, dest_host, dest_port, orig_host, orig_port):
        """Permit direct-tcpip (client-side port forwarding / ProxyJump tunnels)."""
        return True


async def handle_process(process):
    """Interactive shell (PTY + bash) for shell/exec requests; SFTP is served by
    asyncssh's sftp_factory on the same listener."""
    master, slave = pty.openpty()

    def _make_controlling_tty():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    bash = subprocess.Popen(
        ["/bin/bash", "--norc", "-i"],
        stdin=slave, stdout=slave, stderr=slave,
        preexec_fn=_make_controlling_tty, close_fds=True,
    )
    os.close(slave)
    os.set_blocking(master, False)

    def on_resize(width, height, pixwidth, pixheight):
        fcntl.ioctl(master, termios.TIOCSWINSZ,
                    struct.pack("HHHH", height, width, pixwidth or 0, pixheight or 0))

    process.terminal_size_changed = on_resize
    try:
        w, h = process.get_terminal_size() or (80, 24)
        on_resize(w, h, 0, 0)
    except Exception:
        pass

    async def pump_to_client():
        try:
            while True:
                try:
                    data = os.read(master, 65536)
                except BlockingIOError:
                    await asyncio.sleep(0.01)
                    continue
                except OSError:
                    break
                if not data:
                    break
                process.stdout.write(data)
        finally:
            try:
                process.exit(bash.poll() if bash.poll() is not None else 0)
            except Exception:
                pass

    task = asyncio.create_task(pump_to_client())
    try:
        while True:
            data = await process.stdin.read(65536)
            if not data:
                break
            os.write(master, data if isinstance(data, bytes) else data.encode())
    except Exception:
        pass
    finally:
        bash.terminate()
        task.cancel()
        try:
            os.close(master)
        except OSError:
            pass


async def start_test_server(port: int = 10022, authorized_keys: str | None = None):
    os.makedirs(os.path.dirname(HOST_KEY_FILE), exist_ok=True)
    if not os.path.exists(HOST_KEY_FILE):
        key = asyncssh.generate_private_key("ssh-rsa")
        key.write_private_key(HOST_KEY_FILE)
    return await asyncssh.listen(
        "127.0.0.1", port,
        server_factory=lambda: TestSSHServer(authorized_keys),
        process_factory=handle_process,
        server_host_keys=[HOST_KEY_FILE],
        sftp_factory=True,
        encoding=None,
        line_editor=False,
    )

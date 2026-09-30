from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import time
import tomllib
from dataclasses import dataclass, field


@dataclass
class Profile:
    name: str
    host: str
    port: int = 22
    username: str = ""
    password: str | None = None
    password_ref: str | None = None   # "vault:NAME" | "env:VAR" | "keychain:svc/acct" (opt-in)
    key: str | None = None
    key_ref: str | None = None        # "vault:NAME" | "env:VAR" | "keychain:svc/acct" holding a PEM
    accept_unknown_host: bool = False
    known_hosts: str | None = None
    host_fingerprint: str | None = None   # "SHA256:..." pin; verified pre-auth
    jump: str | None = None               # profile name to tunnel through (ProxyJump)

    def public_dict(self) -> dict:
        return {
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "auth": ("key" if (self.key or self.key_ref)
                     else "password_ref" if self.password_ref
                     else ("password" if self.password else "agent/default")),
            "host_key_pinned": bool(self.host_fingerprint),
            "jump": self.jump,
        }


@dataclass
class Settings:
    profiles: dict[str, Profile] = field(default_factory=dict)
    default_profile: str = ""
    max_buffer_bytes: int = 1 << 20
    idle_timeout_sec: int = 1800
    warnings: list[str] = field(default_factory=list)


# --- credential references (resolve-below-the-model) -------------------------
# Resolved plaintexts live only in this process; they are scrubbed from any
# tool output before it reaches the model (see scrub_text).

SECRET_SCRUB: set[str] = set()
SCRUB_MIN_LEN = 4      # values shorter than this cannot be safely scrubbed
SCRUB_FRAG_MIN = 4     # minimum fragment length trimmed/replaced at window edges
SCRUBBED = "[[SCRUBBED]]"


class _VaultStore:
    """Local secrets file (0600). Default credential store — deliberately NOT
    the login keychain: no ACL password prompts, ever (D-12)."""

    def __init__(self):
        self._override: str | None = None

    def vault_path_override(self, path: str | None):
        self._override = path

    def path(self) -> str:
        return self._override or os.path.join(state_dir(), "secrets.json")

    def _load(self) -> dict | None:
        """None = corrupt/unreadable (fail-closed: never auto-clobber)."""
        try:
            fd = os.open(self.path(), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                raw = os.read(fd, 8 * 1024 * 1024)
            finally:
                os.close(fd)
            data = json.loads(raw.decode())
            return data if isinstance(data, dict) else None
        except FileNotFoundError:
            return {}
        except (OSError, ValueError):
            return None

    def vault_get(self, name: str):
        data = self._load()
        if data is None:
            raise ValueError("vault file is corrupt — repair or delete secrets.json first")
        return data.get(name)

    def vault_set(self, name: str, value: str):
        data = self._load()
        if data is None:
            raise ValueError("vault file is corrupt — repair or delete secrets.json first")
        data[name] = value
        path = self.path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        import secrets as _secrets
        tmp = f"{path}.{_secrets.token_hex(4)}.tmp"   # unique tmp: no shared-tmp races
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            buf = json.dumps(data, indent=1).encode()
            while buf:
                buf = buf[os.write(fd, buf):]
        finally:
            os.close(fd)
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


store = _VaultStore()


class SecretResolver:
    """Resolve a password_ref at connect time. Fail-closed on any error."""

    def resolve(self, ref: str) -> str:
        kind, _, rest = ref.partition(":")
        if not rest:
            raise ValueError(f"password_ref {ref!r} is malformed "
                             f"(use vault:NAME, env:VAR, or keychain:service/account)")
        if kind == "vault":
            val = store.vault_get(rest)
            if not val:
                raise ValueError(f"password_ref {ref!r}: no such vault entry")
            return val
        if kind == "env":
            val = os.environ.get(rest)
            if not val:
                raise ValueError(f"password_ref {ref!r}: environment variable {rest!r} is not set")
            return val
        if kind == "keychain":
            service, _, account = rest.partition("/")
            if not account:
                raise ValueError(f"password_ref {ref!r}: account is required "
                                 f"(keychain:service/account)")
            try:
                import keyring
                val = keyring.get_password(service, account)
            except Exception:
                val = None
            if not val:
                raise ValueError(f"password_ref {ref!r}: no such keychain item "
                                 f"(service={service!r} account={account!r})")
            return val
        raise ValueError(f"password_ref {ref!r}: unknown scheme {kind!r} "
                         f"(use vault:NAME, env:VAR, or keychain:service/account)")


def register_secret(value: str):
    if value and len(value) >= SCRUB_MIN_LEN:
        SECRET_SCRUB.add(value)


_RX_CACHE: dict[str, "re.Pattern"] = {}


def _wrap_rx(form: str):
    """Regex tolerating PTY line-wrap noise (spaces / CR) inserted inside the form."""
    rx = _RX_CACHE.get(form)
    if rx is None:
        rx = re.compile(r"\s*".join(re.escape(c) for c in form))
        _RX_CACHE[form] = rx
    return rx


def _secret_forms(value: str) -> list[str]:
    """Transformations an echo/log of the value may take (raw, hex, base64 variants)."""
    b = value.encode()
    forms = [value, b.hex(), base64.b64encode(b).decode(),
             base64.b64encode(b).decode().rstrip("="),
             base64.urlsafe_b64encode(b).decode(),
             base64.urlsafe_b64encode(b).decode().rstrip("="),
             re.sub(r"\s+", "", value)]
    return [f for f in forms if len(f) >= SCRUB_FRAG_MIN]


def _cut_tail(text: str, k: int) -> str:
    """Remove raw trailing chars until k non-whitespace chars consumed."""
    i = len(text)
    seen = 0
    while i > 0 and seen < k:
        i -= 1
        if not text[i].isspace():
            seen += 1
    return text[:i]


def _cut_head(text: str, k: int) -> str:
    i, seen = 0, 0
    while i < len(text) and seen < k:
        if not text[i].isspace():
            seen += 1
        i += 1
    return text[i:]


def scrub_text(text: str) -> str:
    # 1) exact occurrences of any known form, tolerant of PTY wrap noise
    for s in SECRET_SCRUB:
        for form in _secret_forms(s):
            text = _wrap_rx(form).sub(SCRUBBED, text)
    # 2) window-edge fragments: a read window may cut a secret in half; never
    #    return the surviving fragment (the next read gets the whole value).
    for s in SECRET_SCRUB:
        for form in _secret_forms(s):
            n = len(form)
            cond = re.sub(r"\s+", "", text)
            if SCRUB_FRAG_MIN <= len(cond) < n and cond in form:
                return SCRUBBED
            for k in range(SCRUB_FRAG_MIN, n):
                if cond.endswith(form[:k]):
                    text = _cut_tail(text, k) + SCRUBBED
                    break
            cond = re.sub(r"\s+", "", text)
            for k in range(SCRUB_FRAG_MIN, n):
                if cond.startswith(form[n - k:]):
                    text = SCRUBBED + _cut_head(text, k)
                    break
    return text


def audit_event(event: dict):
    """Append-only audit line: names/hosts only, never values."""
    event = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **event}
    line = json.dumps(event) + "\n"
    try:
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(os.path.join(state_dir(), "audit.jsonl"), flags, 0o600)
        try:
            os.write(fd, line.encode())
        finally:
            os.close(fd)
    except OSError as exc:
        import sys
        print(f"[weave-connector] audit write failed: {exc}", file=sys.stderr)


def validate_enroll_source(source: str, kind: str = "password") -> str:
    """Enroll sources are strictly below-model. password: 'dialog' (native
    hidden prompt), 'env:WEAVE_ENROLL_*', or 'file:<path>'. key: 'file:<path>'
    (PEM read from disk). Values are stored in the local vault file (0600) —
    never the login keychain (D-12: no password prompts)."""
    if kind == "key":
        if source.startswith("file:"):
            return source
        raise ValueError("key enrollment source must be 'file:<path to PEM>'")
    if source.startswith("file:"):
        return source
    if source == "dialog":
        return source
    if source.startswith("env:"):
        var = source[4:]
        if re.fullmatch(r"WEAVE_ENROLL_[A-Z0-9_]+", var):
            return source
    raise ValueError("source must be 'dialog' or 'env:WEAVE_ENROLL_<NAME>' "
                     "(secrets never travel in tool arguments)")


def _perm_warnings(path: str, cfg: dict) -> list[str]:
    has_creds = any(("password" in p or "password_ref" in p or "key" in p)
                    for p in cfg.get("profiles", {}).values())  # material or reference
    if not has_creds:
        return []
    mode = os.stat(path).st_mode & 0o777
    if mode & 0o077:
        return [f"{path} is group/world-accessible (mode {oct(mode)}); "
                f"contains credential material or references — chmod 600 recommended"]
    return []


def _expand(p: str | None) -> str | None:
    return os.path.expanduser(p) if p else p


def state_dir() -> str:
    """State directory for daemon/audit/session specs (0700)."""
    d = os.environ.get("WEAVE_CONNECTOR_STATE_DIR") or os.path.expanduser("~/.weave-connector")
    os.makedirs(d, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def resolve_config_path(path: str | None = None) -> str:
    return path or os.environ.get("WEAVE_CONNECTOR_CONFIG") or "config.toml"


def load_settings(path: str | None = None) -> Settings:
    path = resolve_config_path(path)
    if not os.path.exists(path):
        return Settings()
    with open(path, "rb") as f:
        cfg = tomllib.load(f)
    srv = cfg.get("server", {})
    settings = Settings(
        default_profile=srv.get("default_profile", ""),
        max_buffer_bytes=int(srv.get("max_buffer_bytes", 1 << 20)),
        idle_timeout_sec=int(srv.get("idle_timeout_sec", 1800)),
    )
    for name, p in cfg.get("profiles", {}).items():
        settings.profiles[name] = Profile(
            name=name,
            host=p.get("host", ""),
            port=int(p.get("port", 22)),
            username=p.get("username", ""),
            password=p.get("password") or None,
            password_ref=p.get("password_ref") or None,
            key=_expand(p.get("key")),
            key_ref=p.get("key_ref") or None,
            accept_unknown_host=bool(p.get("accept_unknown_host", False)),
            known_hosts=_expand(p.get("known_hosts")),
            host_fingerprint=p.get("host_fingerprint") or None,
            jump=p.get("jump") or None,
        )
    settings.warnings = _perm_warnings(path, cfg)
    return settings

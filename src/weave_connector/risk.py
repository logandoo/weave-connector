"""Command risk classification (best-effort), gate for destructive exec.

Levels (brewtools convention): READ/CREATE free, MODIFY/SERVICE/DELETE/
PRIVILEGE require confirm=True on ssh_shell_exec (and on SFTP mutations).
Raw ssh_shell_write input is NOT gated (escape hatch for TUIs/REPLs) but IS
audited.

Policy (ADR D-9): DELETE/PRIVILEGE keywords match anywhere in the line (a
false positive is a user prompt; a false negative is a destroyed server).
MODIFY tokens match only at command position to keep daily read/scratch
work frictionless; redirects are gated only when the target looks like a
system path. Wrappers (sh -c, interpreters) count as MODIFY because they
hide whatever they run.
"""
from __future__ import annotations

import re

CONFIRM_LEVELS = {"MODIFY", "SERVICE", "DELETE", "PRIVILEGE"}

_ANCHOR = r"(?:^|[;&|]\s*)"

_SYS = r"(?:/etc|/usr|/boot|/System|/Library|/root)(?:/|[\s\"']|$)"

_RULES = [
    # PRIVILEGE — unanchored, case-insensitive: elevation never runs free
    ("PRIVILEGE", re.compile(
        r"(?<![\w/.-])(?:sudo|doas|pkexec|visudo|chroot|setcap|su|useradd|userdel|"
        r"usermod|groupadd|groupdel|passwd|chpasswd|insmod|rmmod|modprobe|kexec|"
        r"grub-install|csrutil|spctl|nvram|profiles)\b"
        r"|\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\|\s*source\b",
        re.IGNORECASE)),
    # DELETE — unanchored, case-insensitive: destructive idioms never run free
    ("DELETE", re.compile(
        r"(?<![\w/.-])(?:rm|shred|unlink|mkfs|fdisk|wipefs|sgdisk|blkdiscard|badblocks)\b"
        r"|\bfind\b[^\n]*\s-delete\b"
        r"|\bgit\s+(?:reset\s+--hard|clean\s+-|push\b[^\n]*--force)\b"
        r"|\brsync\b[^\n]*\s--delete\b"
        r"|\b(?:apt-get|apt)\s+(?:remove|purge)\b|\bdpkg\s+-r\b|\brpm\s+-e\b"
        r"|\bbrew\s+uninstall\b|\bpacman\s+-R\b"
        r"|\b(?:terraform\s+destroy|kubectl\s+delete|vagrant\s+destroy)\b"
        r"|\btmutil\s+delete\b|\bdiskutil\s+erase|\bcrontab\s+-r\b"
        r"|\bdocker\s+(?:rm|kill|system\s+prune|volume\s+rm|image\s+rmi)\b"
        r"|\bnc\b[^\n]*\s-e\b|\bsocat\b[^\n]*exec:",
        re.IGNORECASE)),
    # SERVICE — state-changing service/process ops (read-only subcommands exempt)
    ("SERVICE", re.compile(
        r"\bsystemctl\s+(?!status\b|is-|show\b|list-|cat\b|help\b)"
        r"|\bservice\s+\S+\s+(?:restart|stop|start|reload|enable|disable)\b"
        r"|\b(?:reboot|shutdown|poweroff|halt|launchctl|systemsetup)\b"
        r"|\b(?:init|telinit)\s+[06]\b"
        r"|\bdocker\s+compose\s+(?:down|restart|stop|kill)\b"
        r"|\b(?:kill|pkill|killall|fuser)\s|\bkillall5\b|\bat\s+now\b",
        re.IGNORECASE)),
    # MODIFY — command-position tokens, wrappers, inline-code interpreters,
    # system-path redirects / downloads / extractions. Scratch writes stay free.
    ("MODIFY", re.compile(
        _ANCHOR + r"(?:sed\b(?=[^\n]*(?:\s-\w*i\b|--in-place))|chown|chmod|mv|cp|"
        r"tee|mount|umount|dd\s+(?=[^\n]*\b[io]f=)|mkswap|swapon|swapoff|install|ln|"
        r"eval|source|yq\s+-i|truncate)\b"
        r"|\b(?:perl\s+-(?:pi|e)|python3?\s+-c|node\s+-e|ruby\s+-e|"
        r"(?:ba|z|da|k)?sh\s+-c)\b"
        r"|>{1,2}\s*[\"']?(?:" + _SYS + r"|~/\.|\$HOME/\.|/home/[^/\s]+/\.(?:ssh|bash|zsh))"
        r"|\b(?:wget|curl)\b(?=[^\n]*(?:-O|--output-document|-o)\s*" + _SYS + r")"
        r"|\b(?:tar|unzip)\b(?=[^\n]*(?:\s-C\s+|\s-d\s+)" + _SYS + r")"
        r"|\bsort\b[^\n]*\s-o\s+")),
]

_CREATE_RE = re.compile(_ANCHOR + r"(?:mkdir|touch|tar|unzip|wget|curl|git\s+clone|install)\b")
_DOT_SOURCE = re.compile(_ANCHOR + r"\.\s+")


def classify(command: str) -> str:
    """Return PRIVILEGE / DELETE / SERVICE / MODIFY / CREATE / READ.

    Best-effort static classification of the whole line; highest level wins.
    Misclassification exists in both directions — the confirm gate is a
    backstop, not a sandbox (ssh_shell_write is ungated by design).
    """
    for level, rx in _RULES:
        if rx.search(command):
            return level
    if _DOT_SOURCE.search(command):
        return "MODIFY"
    if _CREATE_RE.search(command):
        return "CREATE"
    return "READ"

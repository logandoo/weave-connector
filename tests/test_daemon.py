"""Daemon persistence e2e: a session opened via MCP server A survives A's death
and is usable via MCP server B (both proxy to the resident daemon).
Evidence: tests/evidence/daemon.log"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import signal
import subprocess
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYTHON = os.path.join(ROOT, ".venv", "bin", "python")
EVIDENCE = os.path.join(os.path.dirname(__file__), "evidence")
STATE = os.path.join(EVIDENCE, "daemon-state")
SOCK = os.path.join(STATE, "daemon.sock")
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ssh_test_server import start_test_server

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}")


def daemon_env():
    env = dict(os.environ)
    env["WEAVE_CONNECTOR_CONFIG"] = os.path.join(STATE, "daemon_config.toml")
    env["WEAVE_CONNECTOR_STATE_DIR"] = STATE
    env["WEAVE_CONNECTOR_DAEMON_SOCK"] = SOCK
    env["WEAVE_CONNECTOR_DAEMON"] = "on"
    return env


async def drive(server_proc_factory, calls):
    """Run calls against a fresh MCP server subprocess; return results."""
    proc = server_proc_factory()
    params = StdioServerParameters(command=PYTHON, args=["-m", "weave_connector.server"],
                                   env=daemon_env())
    out = []
    try:
        async with stdio_client(params) as (r, w):
            async with ClientSession(r, w) as s:
                await s.initialize()
                for tool, args in calls:
                    res = await s.call_tool(tool, args)
                    out.append(json.loads(res.content[0].text if res.content else "{}"))
    finally:
        pass
    return out


def spawn_server():
    return subprocess.Popen([PYTHON, "-m", "weave_connector.server"],
                            env=daemon_env(), stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)


async def main() -> int:
    if os.path.exists(STATE):
        shutil.rmtree(STATE)
    os.makedirs(STATE, exist_ok=True)
    with open(os.path.join(STATE, "daemon_config.toml"), "w") as f:
        f.write('[profiles.local-test]\nhost = "127.0.0.1"\nport = 10022\n'
                'username = "tester"\npassword = "secret"\naccept_unknown_host = true\n')
    ssh_server = await start_test_server(10022)

    # server A opens a named session through the daemon
    out = await drive(spawn_server, [
        ("ssh_shell_open", {"profile": "local-test", "name": "persist-1"}),
    ])
    sid = out[0].get("session_id", "")
    check("daemon_open_via_A", bool(sid), json.dumps(out[0])[:120])

    # bytes seam in daemon mode (raw write) + transcript
    outb = await drive(spawn_server, [
        ("ssh_shell_exec", {"session_id": sid, "command": "true"}),
        ("ssh_shell_read", {"session_id": sid, "cursor": 0}),
        ("ssh_shell_write", {"session_id": sid,
                             "data_base64": "ZWNobyBCWVRFU19PSwo="}),  # echo BYTES_OK\n
    ])
    cur_b = outb[1].get("cursor", 0)
    outb2 = await drive(spawn_server, [
        ("ssh_shell_read", {"session_id": sid, "cursor": cur_b, "wait_ms": 2000}),
    ])
    check("daemon_bytes_write", "BYTES_OK" in json.dumps(outb2[0]),
          f"w={json.dumps(outb[2])[:60]} r={json.dumps(outb2[0])[:120]}")

    # kill any MCP server A child (its stdio session ended already); the daemon lives
    # new server B: session still alive and usable
    out2 = await drive(spawn_server, [
        ("ssh_shell_list", {}),
        ("ssh_shell_exec", {"session_id": sid, "command": "echo SURVIVED"}),
        ("ssh_daemon_status", {}),
    ])
    listed = [t.get("session_id") for t in out2[0].get("sessions", [])]
    check("session_survives_server_death", sid in listed, f"listed={listed}")
    check("exec_via_B", "SURVIVED" in out2[1].get("output", ""), repr(out2[1].get("output"))[:80])
    check("daemon_status", out2[2].get("daemon") is True, json.dumps(out2[2])[:120])

    # dead named session + reopen (reservation must not poison the name)
    outd = await drive(spawn_server, [
        ("ssh_shell_exec", {"session_id": sid, "command": "exit"}),
    ])
    await asyncio.sleep(0.5)
    outr = await drive(spawn_server, [
        ("ssh_shell_open", {"profile": "local-test", "name": "persist-1"}),
    ])
    ok_re = bool(outr[0].get("session_id")) and outr[0].get("session_id") != sid
    check("name_reuse_after_death", ok_re, json.dumps(outr[0])[:120])
    sid2 = outr[0].get("session_id", "")

    # stop daemon cleanly, then a fresh call must respawn and work (C2 recovery)
    out3 = await drive(spawn_server, [("ssh_daemon_stop", {})])
    check("daemon_stop", out3[0].get("stopped") is True, json.dumps(out3[0])[:120])
    outr2 = await drive(spawn_server, [
        ("ssh_shell_open", {"profile": "local-test", "name": "post-stop"}),
    ])
    ok_rec = bool(outr2[0].get("session_id"))
    check("post_stop_recovery", ok_rec, json.dumps(outr2[0])[:120])
    await drive(spawn_server, [("ssh_daemon_stop", {})])
    ssh_server.close()
    await ssh_server.wait_closed()

    with open(os.path.join(EVIDENCE, "daemon.log"), "w") as f:
        for name, ok, detail in RESULTS:
            f.write(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}\n")
        passed = sum(1 for _, ok, _ in RESULTS if ok)
        f.write(f"\nTOTAL {passed}/{len(RESULTS)} PASS\n")
    print(f"\nTOTAL {passed}/{len(RESULTS)} PASS")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

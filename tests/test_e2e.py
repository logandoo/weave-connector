"""End-to-end test: real MCP client (stdio) -> weave-connector server ->
real asyncssh SSH server -> real PTY + bash. Writes evidence to tests/evidence/.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(__file__))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from ssh_test_server import start_test_server, HOST_KEY_FILE

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVIDENCE = os.path.join(os.path.dirname(__file__), "evidence")
PYTHON = os.path.join(ROOT, ".venv", "bin", "python")
PORT = 10022

RESULTS: list[tuple[str, bool, str]] = []
TRANSCRIPT: list[str] = []


def check(name: str, ok: bool, detail: str = ""):
    RESULTS.append((name, ok, detail))
    TRANSCRIPT.append(f"### {name}: {'PASS' if ok else 'FAIL'} {detail}")
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}")


async def call(session: ClientSession, tool: str, args: dict) -> dict:
    TRANSCRIPT.append(f">>> {tool} {json.dumps({k: v for k, v in args.items()})}")
    res = await session.call_tool(tool, args)
    payload = res.content[0].text if res.content else "{}"
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        data = {"raw": payload}
    TRANSCRIPT.append(f"<<< {json.dumps(data)[:2000]}")
    return data


async def main() -> int:
    os.makedirs(EVIDENCE, exist_ok=True)
    import asyncssh as _as
    import tempfile as _tf
    kv_dir = _tf.mkdtemp(prefix="wc-keyvault-")
    kv_key = _as.generate_private_key("ssh-ed25519")
    kv_pem = os.path.join(kv_dir, "keyvault.pem")
    kv_pub = os.path.join(kv_dir, "keyvault.pub")
    kv_key.write_private_key(kv_pem)
    kv_key.convert_to_public().write_public_key(kv_pub)
    server = await start_test_server(PORT, authorized_keys=kv_pub)
    jumper_server = await start_test_server(10040)
    FP_REAL = _as.read_private_key(HOST_KEY_FILE).convert_to_public().get_fingerprint()
    FP_BAD = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    # self-contained test config (repo config.toml no longer carries loopback profiles)
    KC_VALUE = "kc-e2e-password-XYZ123456789"
    EVIL_NAME = 'evil-x" & (do shell script "id") & "y"'  # C1 injection fixture
    test_config = os.path.join(EVIDENCE, "test_config.toml")
    # vault seed (file store — zero keychain interaction)
    os.makedirs(os.path.join(EVIDENCE, "state"), exist_ok=True)
    seed_path = os.path.join(EVIDENCE, "state", "secrets.json")
    with open(seed_path, "w") as f:
        f.write('{"e2e-seed": "%s"}' % KC_VALUE)
    os.chmod(seed_path, 0o600)
    with open(test_config, "w") as f:
        f.write('[server]\nidle_timeout_sec = 1800\n\n'
                '[profiles.local-test]\nhost = "127.0.0.1"\nport = 10022\n'
                'username = "tester"\npassword = "secret"\naccept_unknown_host = true\n'
                '\n[profiles.env-test]\nhost = "127.0.0.1"\nport = 10022\n'
                'username = "tester"\npassword_ref = "env:WC_TEST_PW"\naccept_unknown_host = true\n'
                '\n[profiles.keychain-test]\nhost = "127.0.0.1"\nport = 10022\n'
                'username = "kcuser"\npassword_ref = "vault:e2e-seed"\naccept_unknown_host = true\n'
                '\n[profiles.bad-ref]\nhost = "127.0.0.1"\nport = 10022\n'
                'username = "tester"\npassword_ref = "env:MISSING_WC_VAR"\naccept_unknown_host = true\n'
                f'\n[profiles.fp-ok]\nhost = "127.0.0.1"\nport = 10022\n'
                f'username = "tester"\npassword = "secret"\nhost_fingerprint = "{FP_REAL}"\n'
                f'\n[profiles.fp-bad]\nhost = "127.0.0.1"\nport = 10022\n'
                f'username = "tester"\npassword = "secret"\nhost_fingerprint = "{FP_BAD}"\n'
                '\n[profiles.jumper]\nhost = "127.0.0.1"\nport = 10040\n'
                'username = "tester"\npassword = "secret"\naccept_unknown_host = true\n'
                '\n[profiles.jump-target]\nhost = "127.0.0.1"\nport = 10022\n'
                'username = "tester"\npassword = "secret"\naccept_unknown_host = true\n'
                'jump = "jumper"\n'
                '\n[profiles.enroll-test]\nhost = "127.0.0.1"\nport = 10022\n'
                'username = "tester"\npassword_ref = "vault:enroll-test"\n'
                'accept_unknown_host = true\n'
                '\n[profiles.jump-cycle]\nhost = "127.0.0.1"\nport = 10022\n'
                'username = "tester"\npassword = "secret"\naccept_unknown_host = true\n'
                'jump = "jump-cycle"\n'
                '\n[profiles.keyvault-test]\nhost = "127.0.0.1"\nport = 10022\n'
                'username = "tester"\nkey_ref = "vault:keyvault-test"\n'
                'accept_unknown_host = true\n' 
                + "\n[profiles.\"" + EVIL_NAME.replace("\\", "\\\\").replace('"', '\\"')
                + "\"]\nhost = \"127.0.0.1\"\nport = 10022\nusername = \"tester\"\n"
                'password = "secret"\naccept_unknown_host = true\n')
    import subprocess
    env = dict(os.environ)
    env["WEAVE_CONNECTOR_CONFIG"] = test_config
    env["WC_TEST_PW"] = "secret"
    env["WEAVE_ENROLL_TEST"] = "secret"
    env["WEAVE_CONNECTOR_DAEMON"] = "off"          # e2e = in-process; daemon has its own suite
    env["WEAVE_CONNECTOR_STATE_DIR"] = os.path.join(EVIDENCE, "state")
    params = StdioServerParameters(command=PYTHON, args=["-m", "weave_connector.server"], env=env)
    try:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # 1. profile discovery, no secrets
                r = await call(session, "ssh_list_profiles", {})
                names = [p["name"] for p in r.get("profiles", [])]
                blob = json.dumps(r)
                check("list_profiles", "local-test" in names, f"profiles={names}")
                check("no_secret_leak", "secret" not in blob, "password absent from listing")

                # 2. persistent connection
                r = await call(session, "ssh_connect", {"profile": "local-test"})
                check("connect", r.get("profile") == "local-test", json.dumps(r))

                # 3. open persistent shell
                r = await call(session, "ssh_shell_open", {"profile": "local-test", "cwd": "/tmp"})
                sid = r.get("session_id", "")
                check("shell_open", bool(sid), json.dumps(r))

                # 4. cwd persistence across execs
                await call(session, "ssh_shell_exec", {"session_id": sid, "command": "cd /var"})
                r = await call(session, "ssh_shell_exec", {"session_id": sid, "command": "pwd"})
                check("cwd_persists", "/var" in r.get("output", ""), repr(r.get("output")))

                # 5. env persistence across execs
                await call(session, "ssh_shell_exec", {"session_id": sid, "command": "export WC_FOO=weave42"})
                r = await call(session, "ssh_shell_exec", {"session_id": sid, "command": "echo $WC_FOO"})
                check("env_persists", "weave42" in r.get("output", ""), repr(r.get("output")))

                # 6. exit codes
                r = await call(session, "ssh_shell_exec", {"session_id": sid, "command": "true"})
                ok0 = r.get("exit_code") == 0
                r = await call(session, "ssh_shell_exec", {"session_id": sid, "command": "false"})
                check("exit_codes", ok0 and r.get("exit_code") == 1,
                      f"true->0 false->{r.get('exit_code')}")

                # 7. long-running: timeout keeps running, then await completes
                r = await call(session, "ssh_shell_exec",
                               {"session_id": sid, "command": "sleep 3; echo LONG_DONE", "timeout_ms": 800})
                check("long_timeout_partial", r.get("timeout") is True, json.dumps(r)[:200])
                r = await call(session, "ssh_shell_await", {"session_id": sid, "timeout_ms": 8000})
                check("long_await_done", r.get("completed") and r.get("exit_code") == 0
                      and "LONG_DONE" in r.get("output", ""), json.dumps(r)[:300])

                # 8. interrupt a foreground command with Ctrl-C
                r = await call(session, "ssh_shell_exec",
                               {"session_id": sid, "command": "sleep 60", "timeout_ms": 800})
                cursor = r.get("cursor", 0)
                await call(session, "ssh_shell_signal", {"session_id": sid, "signal": "interrupt"})
                r = await call(session, "ssh_shell_await", {"session_id": sid, "timeout_ms": 8000})
                check("ctrl_c_interrupt", r.get("completed") and r.get("exit_code") == 130,
                      f"exit_code={r.get('exit_code')}")

                # 9. raw write + incremental cursor read
                r = await call(session, "ssh_shell_read", {"session_id": sid, "cursor": 0})
                cur = r.get("cursor", 0)
                await call(session, "ssh_shell_write", {"session_id": sid, "data": "echo RAW_$((6*7))\n"})
                r = await call(session, "ssh_shell_read", {"session_id": sid, "cursor": cur, "wait_ms": 3000})
                check("raw_write_cursor_read", "RAW_42" in r.get("output", ""), repr(r.get("output")))

                # 10. session isolation: second shell has independent cwd
                r2 = await call(session, "ssh_shell_open", {"profile": "local-test"})
                sid2 = r2.get("session_id", "")
                r = await call(session, "ssh_shell_exec", {"session_id": sid2, "command": "pwd"})
                check("session_isolation", r.get("output", "").strip() != "/var",
                      repr(r.get("output")))

                # 11. resize + list + status
                r = await call(session, "ssh_shell_resize", {"session_id": sid2, "cols": 100, "rows": 30})
                ok_resize = r.get("size") == "100x30"
                r = await call(session, "ssh_shell_list", {})
                check("resize_and_list", ok_resize and len(r.get("sessions", [])) == 2,
                      json.dumps(r)[:300])

                # 12. resize propagates to the remote tty
                await call(session, "ssh_shell_resize", {"session_id": sid2, "cols": 100, "rows": 30})
                r = await call(session, "ssh_shell_exec", {"session_id": sid2, "command": "stty size"})
                check("resize_propagates", "30 100" in r.get("output", ""), repr(r.get("output")))

                # 13. marker spoofing from command output cannot fake an exit code
                r = await call(session, "ssh_shell_exec",
                               {"session_id": sid2, "command": "echo __WC_EXIT_0__; false"})
                check("marker_spoof_resisted", r.get("exit_code") == 1, json.dumps(r)[:200])

                # 14. wedge-prone commands are rejected, session stays usable
                r = await call(session, "ssh_shell_exec", {"session_id": sid2, "command": "sleep 5 &"})
                rejected = "error" in r and not r.get("completed")
                r2 = await call(session, "ssh_shell_exec", {"session_id": sid2, "command": "echo OK_AFTER_REJECT"})
                check("reject_background_tail", rejected and "OK_AFTER_REJECT" in r2.get("output", ""),
                      json.dumps(r)[:150])

                # 15. wedged session recovers via ssh_shell_reset
                r = await call(session, "ssh_shell_exec",
                               {"session_id": sid2, "command": 'echo "unterminated', "timeout_ms": 800})
                wedged = r.get("timeout") is True
                r = await call(session, "ssh_shell_reset", {"session_id": sid2})
                recovered = r.get("reset") is True
                r2 = await call(session, "ssh_shell_exec", {"session_id": sid2, "command": "echo AFTER_RESET"})
                check("reset_recovers_wedge", wedged and recovered and "AFTER_RESET" in r2.get("output", ""),
                      json.dumps(r)[:200])

                # 16. base64 raw write path
                import base64 as b64
                r = await call(session, "ssh_shell_read", {"session_id": sid, "cursor": 0})
                cur = r.get("cursor", 0)
                await call(session, "ssh_shell_write",
                           {"session_id": sid, "data_base64": b64.b64encode(b"echo B64_OK\n").decode()})
                r = await call(session, "ssh_shell_read", {"session_id": sid, "cursor": cur, "wait_ms": 3000})
                check("base64_write", "B64_OK" in r.get("output", ""), repr(r.get("output")))

                # 17. close session, connection persists
                await call(session, "ssh_shell_close", {"session_id": sid2})
                r = await call(session, "ssh_shell_exec", {"session_id": sid, "command": "echo STILL_ALIVE"})
                check("close_keeps_conn", "STILL_ALIVE" in r.get("output", ""), repr(r.get("output")))

                # 18. writes to a closed session fail cleanly
                r = await call(session, "ssh_shell_write", {"session_id": sid2, "data": "x"})
                check("write_closed_errors", "error" in r, json.dumps(r)[:200])

                # 19. unknown session errors cleanly
                r = await call(session, "ssh_shell_exec", {"session_id": "deadbeef0000", "command": "x"})
                check("bad_session_errors", "error" in r, json.dumps(r)[:200])

                # 20. config hot-reload: a profile added after server start becomes usable
                with open(test_config, "a") as f:
                    f.write('\n[profiles.dynamic]\nhost = "127.0.0.1"\nport = 10022\n'
                            'username = "tester"\npassword = "secret"\naccept_unknown_host = true\n')
                r = await call(session, "ssh_list_profiles", {})
                names = [p["name"] for p in r.get("profiles", [])]
                check("hot_reload_listed", "dynamic" in names, f"profiles={names}")
                r = await call(session, "ssh_shell_open", {"profile": "dynamic"})
                sid3 = r.get("session_id", "")
                r = await call(session, "ssh_shell_exec", {"session_id": sid3, "command": "echo HOT_RELOAD_OK"})
                check("hot_reload_usable", "HOT_RELOAD_OK" in r.get("output", ""), repr(r.get("output")))
                await call(session, "ssh_shell_close", {"session_id": sid3})

                await call(session, "ssh_disconnect", {"profile": "local-test"})

                # 21. env-ref profile authenticates without plaintext password
                r = await call(session, "ssh_shell_open", {"profile": "env-test"})
                sid4 = r.get("session_id", "")
                r = await call(session, "ssh_shell_exec", {"session_id": sid4, "command": "echo ENV_REF_OK"})
                ok_env = "ENV_REF_OK" in r.get("output", "")
                await call(session, "ssh_shell_close", {"session_id": sid4})
                check("env_ref_authenticates", ok_env, repr(r.get("output"))[:120])

                # 22/24. vault-ref authenticates and its value is scrubbed from output
                if True:  # vault runs everywhere (D-12)
                    r = await call(session, "ssh_shell_open", {"profile": "keychain-test"})
                    sid5 = r.get("session_id", "")
                    r = await call(session, "ssh_shell_exec",
                                   {"session_id": sid5, "command": f"echo {KC_VALUE}"})
                    out = r.get("output", "")
                    check("keychain_ref_authenticates", bool(sid5) and "[[SCRUBBED]]" in out,
                          repr(out)[:160])
                    check("secret_scrubbed", KC_VALUE not in out, "value absent from returned output")

                    # 24b. window-split scrub: no fragment of the secret survives any read window
                    r = await call(session, "ssh_shell_read", {"session_id": sid5, "cursor": 0})
                    cur = r.get("cursor", 0)
                    await call(session, "ssh_shell_write",
                               {"session_id": sid5, "data": "printf '%s' '" + ("Z" * 200) + KC_VALUE + "'\n"})
                    windows, guard = [], 0
                    while guard < 40:
                        guard += 1
                        r = await call(session, "ssh_shell_read",
                                       {"session_id": sid5, "cursor": cur, "max_bytes": 64, "wait_ms": 1500})
                        windows.append(r.get("output", ""))
                        nxt = r.get("cursor", cur)
                        if nxt == cur:
                            break
                        cur = nxt
                    leak = any((KC_VALUE in w) or any(KC_VALUE[i:i + 6] in w
                               for i in range(len(KC_VALUE) - 5)) for w in windows)
                    check("window_split_scrubbed", not leak,
                          f"{len(windows)} windows, no fragment >=6 chars")
                    await call(session, "ssh_shell_close", {"session_id": sid5})

                # 23. unresolvable ref fails closed, error carries no secret material
                r = await call(session, "ssh_shell_open", {"profile": "bad-ref"})
                err = json.dumps(r)
                check("bad_ref_fails_closed", "error" in r and "MISSING_WC_VAR" in err,
                      err[:160])

                # 25. audit trail exists, records ref use, never values
                audit_path = os.path.join(EVIDENCE, "state", "audit.jsonl")
                if os.path.exists(audit_path):
                    audit_txt = open(audit_path).read()
                    # must record the ref actually used this run; never values
                    check("audit_logged", "vault:e2e-seed" in audit_txt and KC_VALUE not in audit_txt,
                          f"{len(audit_txt)} bytes")
                else:
                    check("audit_logged", False, "audit.jsonl missing")

                # 26. config perms warning: 600 -> clean, 644 -> warned (transition, both halves)
                os.chmod(test_config, 0o600)
                os.utime(test_config)
                r = await call(session, "ssh_status", {})
                clean = len(r.get("warnings", [])) == 0
                os.chmod(test_config, 0o644)
                os.utime(test_config)
                r = await call(session, "ssh_status", {})
                warns = json.dumps(r.get("warnings", []))
                check("perm_warning", clean and ("permission" in warns.lower() or "0644" in warns or "644" in warns),
                      f"600-clean={clean} 644-warn={warns[:100]}")

                # 27. SFTP round-trip over the persistent connection
                r = await call(session, "ssh_sftp_write",
                               {"profile": "local-test", "remote_path": "/tmp/wc_sftp_test.txt",
                                "content": "hello-sftp-123", "confirm": True})
                ok_w = r.get("written_bytes") == len("hello-sftp-123")
                r = await call(session, "ssh_sftp_read",
                               {"profile": "local-test", "remote_path": "/tmp/wc_sftp_test.txt"})
                ok_r = "hello-sftp-123" in r.get("content", "")
                r = await call(session, "ssh_sftp_list",
                               {"profile": "local-test", "remote_path": "/tmp"})
                names = [e["name"] for e in r.get("entries", [])]
                ok_l = "wc_sftp_test.txt" in names
                with open(os.path.join(EVIDENCE, "sftp_local_up.txt"), "w") as f:
                    f.write("upload-payload-456")
                r = await call(session, "ssh_sftp_upload",
                               {"profile": "local-test",
                                "local_path": os.path.join(EVIDENCE, "sftp_local_up.txt"),
                                "remote_path": "/tmp/wc_sftp_up.txt", "confirm": True})
                ok_u = r.get("uploaded_bytes") == len("upload-payload-456")
                down_path = os.path.join(EVIDENCE, "sftp_local_down.txt")
                r = await call(session, "ssh_sftp_download",
                               {"profile": "local-test", "remote_path": "/tmp/wc_sftp_up.txt",
                                "local_path": down_path, "confirm": True, "overwrite": True})
                ok_d = (os.path.exists(down_path)
                        and open(down_path).read() == "upload-payload-456")
                check("sftp_roundtrip", ok_w and ok_r and ok_l and ok_u and ok_d,
                      f"w={ok_w} r={ok_r} l={ok_l} u={ok_u} d={ok_d}")

                # 27b. SFTP mutations gated + local overwrite refusal
                r = await call(session, "ssh_sftp_write",
                               {"profile": "local-test", "remote_path": "/tmp/wc_gate.txt",
                                "content": "x"})
                sftp_gated = r.get("requires_confirm") is True and r.get("risk_level") == "MODIFY"
                r = await call(session, "ssh_sftp_download",
                               {"profile": "local-test", "remote_path": "/tmp/wc_sftp_up.txt",
                                "local_path": down_path, "confirm": True})
                no_clobber = "error" in r and "overwrite" in r.get("error", "")
                check("sftp_gate_and_no_clobber", sftp_gated and no_clobber,
                      f"gated={sftp_gated} no_clobber={no_clobber}")

                # 27c. bootstrap bypass: env values containing gate keywords still open
                r = await call(session, "ssh_shell_open",
                               {"profile": "local-test", "env": {"NOTE": "rm me"}})
                sid7 = r.get("session_id", "")
                r2 = await call(session, "ssh_shell_exec",
                                {"session_id": sid7, "command": "echo BOOT_OK"}) if sid7 else {}
                ok_boot = "BOOT_OK" in r2.get("output", "")
                if sid7:
                    await call(session, "ssh_shell_close", {"session_id": sid7})
                check("bootstrap_gate_bypass", ok_boot, "env token rm forces DELETE w/o bypass")

                # 28. destructive command gated on confirm, with risk class
                r = await call(session, "ssh_shell_open", {"profile": "local-test"})
                sid6 = r.get("session_id", "")
                r = await call(session, "ssh_shell_exec",
                               {"session_id": sid6, "command": "rm /tmp/wc_sftp_test.txt"})
                gated = (r.get("error", "").find("confirm") >= 0 or r.get("requires_confirm") is True) \
                        and r.get("risk_level") == "DELETE"
                r = await call(session, "ssh_shell_exec",
                               {"session_id": sid6, "command": "rm /tmp/wc_sftp_test.txt",
                                "confirm": True})
                ran = r.get("completed") and r.get("exit_code") == 0
                check("risk_gate_confirm", gated and ran, f"gated={gated} ran={ran}")
                await call(session, "ssh_shell_close", {"session_id": sid6})

                # 29. host fingerprint pinning: wrong fp refused, right fp connects
                r = await call(session, "ssh_connect", {"profile": "fp-bad"})
                bad_refused = "error" in r
                r = await call(session, "ssh_connect", {"profile": "fp-ok"})
                ok_accepted = r.get("profile") == "fp-ok"
                check("host_fingerprint_pin", bad_refused and ok_accepted,
                      f"bad_refused={bad_refused} ok_accepted={ok_accepted}")

                # 30. skill discipline pack present (doc check)
                skill_path = os.path.join(ROOT, ".opencode", "skills", "ssh-connector", "SKILL.md")
                sk = open(skill_path).read()
                ok_doc = all(t in sk for t in ("PRIVILEGE", "DELETE", "confirm", "budget", "READ"))
                check("skill_risk_pack", ok_doc, f"{len(sk)} chars")

                # 31. named sessions: idempotent reuse + name visible
                r = await call(session, "ssh_shell_open", {"profile": "local-test", "name": "named-a"})
                sidA = r.get("session_id", "")
                r = await call(session, "ssh_shell_open", {"profile": "local-test", "name": "named-a"})
                sidA2 = r.get("session_id", "")
                r = await call(session, "ssh_shell_list", {})
                names_listed = [t.get("name") for t in r.get("sessions", [])]
                check("named_session_reuse", bool(sidA) and sidA == sidA2 and "named-a" in names_listed,
                      f"ids={sidA}/{sidA2} names={names_listed}")
                if sidA:
                    await call(session, "ssh_shell_close", {"session_id": sidA})

                # 32. port forward round-trip through the SSH connection
                import socket as _sock

                async def _echo(reader, writer):
                    data = await reader.read(1024)
                    writer.write(b"ECHO:" + data)
                    await writer.drain()
                    writer.close()

                echo_srv = await asyncio.start_server(_echo, "127.0.0.1", 0)
                echo_port = echo_srv.sockets[0].getsockname()[1]
                global echo_port2
                echo_port2 = echo_port
                r = await call(session, "ssh_forward_open",
                               {"profile": "local-test", "local_port": 0,
                                "remote_host": "127.0.0.1", "remote_port": echo_port})
                fid = r.get("forward_id", "")
                lport = r.get("local_port", 0)
                ok_fwd = False
                if fid and lport:
                    try:
                        rd, wr = await asyncio.open_connection("127.0.0.1", lport)
                        wr.write(b"ping")
                        await wr.drain()
                        got = await asyncio.wait_for(rd.read(64), 5)
                        ok_fwd = got == b"ECHO:ping"
                        wr.close()
                    except Exception as e:
                        ok_fwd = False
                r = await call(session, "ssh_forward_list", {})
                fids = [f.get("forward_id") for f in r.get("forwards", [])]
                await call(session, "ssh_forward_close", {"forward_id": fid})
                echo_srv.close()
                await echo_srv.wait_closed()
                check("forward_roundtrip", ok_fwd and fid in fids,
                      f"fwd={ok_fwd} listed={fid in fids}")

                # 33. ProxyJump: target reached through jumper profile
                r = await call(session, "ssh_shell_open", {"profile": "jump-target"})
                sidJ = r.get("session_id", "")
                r2 = await call(session, "ssh_shell_exec",
                                {"session_id": sidJ, "command": "echo VIA_JUMP"}) if sidJ else {}
                ok_jump = "VIA_JUMP" in r2.get("output", "")
                if sidJ:
                    await call(session, "ssh_shell_close", {"session_id": sidJ})
                check("proxyjump_exec", ok_jump, repr(r)[:120])

                # 34. credential enroll via restricted env source -> keychain -> auth
                r = await call(session, "ssh_credential_enroll",
                               {"profile": "enroll-test", "source": "env:WEAVE_ENROLL_TEST"})
                ok_enroll = r.get("stored") is True
                r2 = await call(session, "ssh_shell_open", {"profile": "enroll-test"})
                sidE = r2.get("session_id", "")
                r3 = await call(session, "ssh_shell_exec",
                                {"session_id": sidE, "command": "echo ENROLL_OK"}) if sidE else {}
                ok_auth = "ENROLL_OK" in r3.get("output", "")
                if sidE:
                    await call(session, "ssh_shell_close", {"session_id": sidE})
                import subprocess as _sp
                check("credential_enroll", ok_enroll and ok_auth,
                      f"stored={ok_enroll} auth={ok_auth}")

                # 35. tool annotations exposed via tools/list
                tools = await session.list_tools()
                ann = {t.name: t.annotations for t in tools.tools}
                a_write = ann.get("ssh_sftp_write")
                a_read = ann.get("ssh_shell_list")
                ok_ann = (a_write is not None and getattr(a_write, "destructiveHint", None) is True
                          and a_read is not None and getattr(a_read, "readOnlyHint", None) is True)
                check("tool_annotations", ok_ann,
                      f"write={a_write} list={a_read}")

                # 35b. annotation surface: write/signal/enroll marked destructive
                a_w = ann.get("ssh_shell_write")
                a_sig = ann.get("ssh_shell_signal")
                a_en = ann.get("ssh_credential_enroll")
                ok_ann2 = all(getattr(a, "destructiveHint", None) is True
                              for a in (a_w, a_sig, a_en))
                check("annotations_surface", ok_ann2,
                      f"write={getattr(a_w,'destructiveHint',None)} "
                      f"signal={getattr(a_sig,'destructiveHint',None)} "
                      f"enroll={getattr(a_en,'destructiveHint',None)}")

                # 36b. jump cycle refused (no deadlock)
                r = await call(session, "ssh_connect", {"profile": "jump-cycle"})
                check("jump_cycle_refused", "error" in r and "cycle" in r.get("error", "").lower(),
                      json.dumps(r)[:140])

                # 36c. name-only reuse works; explicit different profile refused
                r0 = await call(session, "ssh_shell_open", {"profile": "local-test", "name": "named-a"})
                sidN = r0.get("session_id", "")
                r = await call(session, "ssh_shell_open", {"name": "named-a"})
                ok_reuse = r.get("reused") is True and r.get("session_id") == sidN
                r = await call(session, "ssh_shell_open",
                               {"profile": "env-test", "name": "named-a"})
                ok_xref = "error" in r and "bound to" in r.get("error", "") \
                          and "session_id" not in r
                rlist = await call(session, "ssh_shell_list", {})
                for t in rlist.get("sessions", []):
                    if t.get("name") == "named-a" and t.get("alive"):
                        await call(session, "ssh_shell_close", {"session_id": t["session_id"]})
                check("name_cross_profile_refused", ok_reuse and ok_xref,
                      f"reuse={ok_reuse} xref={ok_xref}")

                # 36d. forward registry cleaned on disconnect
                r = await call(session, "ssh_forward_open",
                               {"profile": "local-test", "local_port": 0,
                                "remote_host": "127.0.0.1", "remote_port": echo_port2})
                fid2 = r.get("forward_id", "")
                await call(session, "ssh_disconnect", {"profile": "local-test"})
                r = await call(session, "ssh_forward_list", {})
                fids2 = [f.get("forward_id") for f in r.get("forwards", [])]
                check("forward_ghost_cleanup", bool(fid2) and fid2 not in fids2,
                      f"opened={bool(fid2)} still_listed={fid2 in fids2}")

                # 36e. AppleScript-injection profile name refused by enroll (C1 net)
                r = await call(session, "ssh_credential_enroll",
                               {"profile": EVIL_NAME, "source": "dialog"})
                ok_evil = "error" in r and "unsafe" in r.get("error", "")
                check("enroll_name_safety", ok_evil, json.dumps(r)[:160])

                # 36f. sessions.json: no env values, 0600, untracked, corrupt-file non-brick
                sj = os.path.join(EVIDENCE, "state", "sessions.json")
                if os.path.exists(sj):
                    txt = open(sj).read()
                    ok_clean = KC_VALUE not in txt and "secret" not in txt and "NOTE" in txt
                    ok_perm = (os.stat(sj).st_mode & 0o777) == 0o600
                else:
                    ok_clean, ok_perm = True, True
                import subprocess as _sp2
                tracked = _sp2.run(["git", "ls-files", "sessions.json"], cwd=ROOT,
                                   capture_output=True, text=True).stdout.strip()
                ok_untracked = tracked == ""
                with open(sj, "w") as f:
                    f.write("{{{corrupt")
                r = await call(session, "ssh_shell_open", {"profile": "local-test", "name": "brick-test"})
                ok_nobrick = bool(r.get("session_id"))
                if ok_nobrick:
                    await call(session, "ssh_shell_close", {"session_id": r["session_id"]})
                if os.path.exists(sj):
                    os.unlink(sj)  # probe must not poison the next run

                # 43. transcripts: opt-in record, scrubbed output
                r = await call(session, "ssh_shell_open",
                               {"profile": "local-test", "name": "rec-1", "record": True})
                sidR = r.get("session_id", "")
                await call(session, "ssh_shell_exec",
                           {"session_id": sidR, "command": f"echo {KC_VALUE}"})
                r = await call(session, "ssh_shell_transcript", {"session_id": sidR})
                tr = r.get("transcript", "")
                ok_tr = bool(sidR) and "[[SCRUBBED]]" in tr and KC_VALUE not in tr
                if sidR:
                    await call(session, "ssh_shell_close", {"session_id": sidR})
                check("transcript_scrubbed", ok_tr, f"{len(tr)} bytes")

                # 44. key vault: enroll kind=key file:source -> key_ref auth
                r = await call(session, "ssh_credential_enroll",
                               {"profile": "keyvault-test", "kind": "key",
                                "source": f"file:{kv_pem}", "confirm": True})
                ok_store = r.get("stored") is True and r.get("kind") == "key"
                r2 = await call(session, "ssh_shell_open", {"profile": "keyvault-test"})
                sidK = r2.get("session_id", "")
                r3 = await call(session, "ssh_shell_exec",
                                {"session_id": sidK, "command": "echo KEYVAULT_OK"}) if sidK else {}
                ok_keyauth = "KEYVAULT_OK" in r3.get("output", "")
                if sidK:
                    await call(session, "ssh_shell_close", {"session_id": sidK})
                check("keyvault_ref_auth", ok_store and ok_keyauth,
                      f"stored={ok_store} auth={ok_keyauth}")

                # 45b. password file: source gated on confirm + empty-file refused
                empty_f = os.path.join(kv_dir, "empty.txt")
                open(empty_f, "w").close()
                r = await call(session, "ssh_credential_enroll",
                               {"profile": "enroll-test", "source": f"file:{empty_f}"})
                ok_gate = r.get("requires_confirm") is True
                r = await call(session, "ssh_credential_enroll",
                               {"profile": "enroll-test", "source": f"file:{empty_f}",
                                "confirm": True})
                ok_empty = "error" in r and "empty" in r.get("error", "")
                check("file_source_gated", ok_gate and ok_empty,
                      f"gate={ok_gate} empty={ok_empty}")

                # 45. key enroll gated on confirm
                r = await call(session, "ssh_credential_enroll",
                               {"profile": "keyvault-test", "kind": "key",
                                "source": f"file:{kv_pem}"})
                check("key_enroll_confirm_gate",
                      r.get("requires_confirm") is True and "confirm" in r.get("error", ""),
                      json.dumps(r)[:120])
                check("sessions_json_clean", ok_clean and ok_perm and ok_untracked and ok_nobrick,
                      f"clean={ok_clean} perm0600={ok_perm} untracked={ok_untracked} "
                      f"corrupt_non_brick={ok_nobrick}")
    except Exception:
        traceback.print_exc()
        check("harness_crash", False, "exception during run")
    finally:
        server.close()
        await server.wait_closed()
        jumper_server.close()
        await jumper_server.wait_closed()

    with open(os.path.join(EVIDENCE, "e2e_transcript.log"), "w") as f:
        f.write("\n".join(TRANSCRIPT) + "\n")
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    total = len(RESULTS)
    with open(os.path.join(EVIDENCE, "e2e_results.log"), "w") as f:
        for name, ok, detail in RESULTS:
            f.write(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}\n")
        f.write(f"\nTOTAL {passed}/{total} PASS\n")
    print(f"\nTOTAL {passed}/{total} PASS")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

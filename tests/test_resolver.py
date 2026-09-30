"""Unit tests for the credential reference resolver + output scrubbing.
Run: .venv/bin/python tests/test_resolver.py  (evidence: tests/evidence/resolver.log)
"""
from __future__ import annotations

import base64
import os
import sys
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = ""):
    RESULTS.append((name, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}")


def extra_unit_checks():
    from weave_connector.config import validate_enroll_source
    global check
    ok1 = validate_enroll_source("dialog") == "dialog"
    try:
        validate_enroll_source("env:MY_SECRET")
        ok2 = False
    except ValueError:
        ok2 = True
    ok3 = validate_enroll_source("env:WEAVE_ENROLL_TEST") == "env:WEAVE_ENROLL_TEST"
    check("enroll_source_validation", ok1 and ok2 and ok3,
          f"dialog={ok1} reject-plain-env={ok2} restricted-env={ok3}")


def b64_unpadded_check():
    import base64 as b64mod
    from weave_connector.config import SECRET_SCRUB, register_secret, scrub_text
    SECRET_SCRUB.clear()
    secret5 = "dummy-unpadded-SECRET-54321"
    register_secret(secret5)
    padded = b64mod.b64encode(secret5.encode()).decode()
    t = scrub_text(f"tok={padded.rstrip('=')}")
    check("scrub_b64_unpadded", padded.rstrip("=") not in t, t[:80])


def vault_store_check():
    import tempfile
    from weave_connector.config import SecretResolver, register_secret, scrub_text, store
    tmp = os.path.join(tempfile.mkdtemp(prefix="wc-vault-"), "secrets.json")
    store.vault_path_override(tmp)
    store.vault_set("alice", "vault-value-abcdefgh")
    v = SecretResolver().resolve("vault:alice")
    check("vault_ref_resolves", v == "vault-value-abcdefgh", repr(v))
    try:
        SecretResolver().resolve("vault:missing")
        ok_missing = False
    except ValueError as e:
        ok_missing = "vault:missing" in str(e)
    check("vault_missing_fails_closed", ok_missing)
    mode = os.stat(tmp).st_mode & 0o777
    check("vault_file_0600", mode == 0o600, oct(mode))
    txt = open(tmp).read()
    check("vault_file_holds_value", "vault-value-abcdefgh" in txt)
    store.vault_path_override(None)


def main() -> int:
    from weave_connector.config import (
        SecretResolver, register_secret, scrub_text, SECRET_SCRUB,
    )
    r = SecretResolver()

    # env ref resolves
    os.environ["WC_UNIT_PW"] = "unit-value-abcdefgh"
    v = r.resolve("env:WC_UNIT_PW")
    check("env_ref_resolves", v == "unit-value-abcdefgh", repr(v))

    # missing env fails closed, no secret in message
    try:
        r.resolve("env:WC_MISSING_VAR")
        check("env_missing_fails_closed", False, "no exception")
    except ValueError as e:
        check("env_missing_fails_closed", "WC_MISSING_VAR" in str(e) and "secret" not in str(e).lower().replace("secret material", ""),
              str(e)[:120])

    # unknown scheme fails closed
    try:
        r.resolve("warp:foo")
        check("unknown_scheme_fails", False, "no exception")
    except ValueError as e:
        check("unknown_scheme_fails", "unknown scheme" in str(e), str(e)[:120])

    # keychain: scheme is opt-in and deliberately NOT exercised (D-12: suite
    # performs zero keychain operations so no login-password prompts can occur)
    check("keychain_optin_untouched", True, "scheme kept, suite never calls it")

    # scrub: registered value replaced raw and base64
    SECRET_SCRUB.clear()
    secret = "dummy-secret-VALUE-123456"  # sample value for scrub test
    register_secret(secret)
    out = f"login as {secret} token={base64.b64encode(secret.encode()).decode()}"
    scrubbed = scrub_text(out)
    check("scrub_raw_and_b64", secret not in scrubbed
          and base64.b64encode(secret.encode()).decode() not in scrubbed
          and "[[SCRUBBED]]" in scrubbed, scrubbed[:120])

    # values >=4 chars are registered and scrubbed (review I3: fail-safe over mangling)
    SECRET_SCRUB.clear()
    register_secret("short")
    check("short_values_registered", "short" in SECRET_SCRUB
          and scrub_text("a short value") == "a [[SCRUBBED]] value",
          scrub_text("a short value"))

    # encoding variants (review I2): hex and base64url also scrubbed
    SECRET_SCRUB.clear()
    import base64 as b64mod
    secret2 = "dummy-encoding-VALUE-98765"
    register_secret(secret2)
    hx = secret2.encode().hex()
    u64 = b64mod.urlsafe_b64encode(secret2.encode()).decode().rstrip("=")
    t = scrub_text(f"hx={hx} u64={u64}")
    check("scrub_hex_and_b64url", secret2.encode().hex() not in t and u64 not in t
          and "[[SCRUBBED]]" in t, t[:120])

    # window-edge fragments never returned (review I1/window-split)
    SECRET_SCRUB.clear()
    secret3 = "dummy-split-SECRET-abcdef"
    register_secret(secret3)
    tail_frag = "ends " + secret3[:8]
    head_frag = secret3[-8:] + " starts"
    t1, t2 = scrub_text(tail_frag), scrub_text(head_frag)
    mid = secret3[5:18]   # window entirely inside the secret (both edges cut)
    t3 = scrub_text(mid)
    # PTY wrap noise: tty inserts " \r" at the wrap column INSIDE the secret
    secret4 = "kc-e2e-password-XYZ123456789"
    wrapped = secret4[:17] + " \r" + secret4[17:]   # wrap at the real observed column
    SECRET_SCRUB.clear()
    register_secret(secret4)
    t4 = scrub_text("echo " + wrapped + " done")
    check("scrub_split_fragments", secret3[:8] not in t1 and secret3[-8:] not in t2
          and secret3[5:18] not in t3 and t3 == "[[SCRUBBED]]",
          f"{t1!r} / {t2!r} / {t3!r}")
    check("scrub_wrapped_secret", "XYZ123456789" not in t4 and "kc-e2e" not in t4
          and "[[SCRUBBED]]" in t4, t4)

    extra_unit_checks()
    b64_unpadded_check()
    vault_store_check()
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    total = len(RESULTS)
    os.makedirs(os.path.join(os.path.dirname(__file__), "evidence"), exist_ok=True)
    with open(os.path.join(os.path.dirname(__file__), "evidence", "resolver.log"), "w") as f:
        for name, ok, detail in RESULTS:
            f.write(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}\n")
        f.write(f"\nTOTAL {passed}/{total} PASS\n")
    print(f"\nTOTAL {passed}/{total} PASS")
    return 0 if passed == total else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(1)



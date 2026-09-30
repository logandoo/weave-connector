#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
.venv/bin/python tests/test_resolver.py 2>&1 | tee tests/evidence/resolver_run.log
.venv/bin/python tests/test_risk.py 2>&1 | tee tests/evidence/risk_run.log
.venv/bin/python tests/test_e2e.py 2>&1 | tee tests/evidence/e2e_run.log
.venv/bin/python tests/test_daemon.py 2>&1 | tee tests/evidence/daemon_run.log

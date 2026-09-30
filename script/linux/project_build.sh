#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
export PIP_INDEX_URL="${PIP_INDEX_URL:-https://pypi.org/simple}"
PY="${PYTHON_BIN:-python3.13}"
command -v "$PY" >/dev/null || PY=python3
if [ ! -x .venv/bin/python ]; then
  "$PY" -m venv .venv
fi
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -e .
.venv/bin/pip install -q pytest
echo "build ok: $(.venv/bin/python --version)"

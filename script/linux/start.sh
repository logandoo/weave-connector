#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p logs
if [ -f .pid ] && kill -0 "$(cat .pid)" 2>/dev/null; then
  echo "already running (pid $(cat .pid))"; exit 0
fi
export WEAVE_CONNECTOR_CONFIG="${WEAVE_CONNECTOR_CONFIG:-config.toml}"
nohup .venv/bin/python -m weave_connector.server > logs/server.log 2>&1 &
echo $! > .pid
echo "started pid $(cat .pid) — stdio MCP server; normally launched by your MCP host via opencode.json"

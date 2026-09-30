#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
if [ -f .pid ]; then
  PID="$(cat .pid)"
  if kill -0 "$PID" 2>/dev/null; then
    kill "$PID"
    echo "stopped pid $PID"
  else
    echo "pid $PID not running"
  fi
  rm -f .pid
else
  echo "no .pid file"
fi

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
bash script/linux/stop.sh || true
bash script/linux/start.sh

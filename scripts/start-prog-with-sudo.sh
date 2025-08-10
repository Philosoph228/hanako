#!/usr/bin/env bash
set -euo pipefail

PROG="${1:-}"
shift || true
# optional drop leading --
if [[ "${1:-}" == "--" ]]; then shift || true; fi

if [[ -z "$PROG" ]]; then
  echo "Usage: $0 /path/to/binary [-- args...]"
  exit 2
fi

# start the program as root in background; write PID to a file (optional)
sudo "$PROG" "$@" &
echo $! > /tmp/last_debugged_pid
sleep 0.05
#!/usr/bin/env bash
set -euo pipefail

PROG="${1:-}"
shift || true

if [[ -z "$PROG" || ! -x "$PROG" ]]; then
  echo "Usage: $0 /path/to/binary [args...] (and binary must be executable)"
  exit 2
fi

# find lldb-server (same logic as before)
LLDB_SERVER="$(command -v lldb-server || true)"
if [[ -z "$LLDB_SERVER" ]]; then
  for p in /usr/bin/lldb-server-* /usr/lib/llvm-*/bin/lldb-server*; do
    [[ -x "$p" ]] && { LLDB_SERVER="$p"; break; }
  done
fi
if [[ -z "$LLDB_SERVER" ]]; then
  echo "lldb-server not found; install lldb."
  exit 3
fi

PORT=12345
LOG="/tmp/lldb-server-${PORT}.log"
PIDFILE="/tmp/lldb-server-${PORT}.pid"

echo "Using lldb-server: $LLDB_SERVER"
echo "Starting lldb-server on :${PORT} for ${PROG} (WAIT_FOR_DEBUGGER=1)"
# require sudo non-interactive (you said you have NOPASSWD); abort if not
if ! sudo -n true 2>/dev/null; then
  echo "sudo would prompt for password; configure NOPASSWD or run manually."
  exit 4
fi

# Start lldb-server with WAIT_FOR_DEBUGGER in its environment so its child inherits it.
sudo bash -c "nohup env WAIT_FOR_DEBUGGER=1 \"$LLDB_SERVER\" gdbserver :${PORT} -- \"${PROG}\" \"$@\" >\"${LOG}\" 2>&1 & echo \$! >\"${PIDFILE}\""

# wait for listen (same robust loop as earlier)...
# [omitted here for brevity — keep the port-wait loop from previous script]

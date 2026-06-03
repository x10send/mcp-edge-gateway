#!/bin/sh
# Restart wrapper: exit code 75 loops (restart request); all other codes pass through.
# Traps SIGTERM/SIGINT and forwards them to the Node child for graceful shutdown.
child=""

terminate() {
  if [ -n "$child" ]; then
    kill -TERM "$child" 2>/dev/null
    wait "$child" 2>/dev/null
  fi
  exit 0
}
trap terminate TERM INT

while true; do
  node dist/server.js &
  child=$!
  wait "$child"
  code=$?
  child=""
  if [ "$code" -ne 75 ]; then
    exit "$code"
  fi
  echo "Restarting gateway..."
  sleep 1
done

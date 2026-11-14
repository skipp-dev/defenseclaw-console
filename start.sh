#!/bin/bash
# Starts the DefenseClaw Console (127.0.0.1:18990 only). The URL with the key is written to URL.txt.
cd "$(dirname "$0")" || exit 1
umask 077
PY="${DEFENSECLAW_CONSOLE_PYTHON:-$HOME/.defenseclaw/.venv/bin/python}"
if [ ! -x "$PY" ]; then
  PY="$(command -v python3)"
fi
if [ -z "$PY" ]; then
  echo "No Python 3 found. Set DEFENSECLAW_CONSOLE_PYTHON." >&2
  exit 1
fi
exec "$PY" -I console/server.py

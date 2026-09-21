#!/usr/bin/env bash
# Usage:
#   ./start.sh              → https://thismachine.localhost:5000
#   PORT=8080 ./start.sh   → https://thismachine.localhost:8080
#   TERMSITE_HOST=0.0.0.0 TERMSITE_PORT=9000 ./start.sh  (not recommended — exposes to network)
#
# HTTPS: a self-signed cert is auto-generated in ~/.termsite_cert/ on first run.
# Accept it once in the browser (Advanced → Proceed). For a green padlock, see
# mkcert instructions printed at startup.
#
# Port: *.localhost resolves to 127.0.0.1 in Chrome 69+ / Firefox 75+ without
# DNS changes. For no ':5000' in the URL, bind to port 443 with:
#   sudo setcap cap_net_bind_service=+ep $(readlink -f $(which python3))
# then set PORT=443 when launching.

set -euo pipefail
cd "$(dirname "$0")"

VENV=".venv"

if [ ! -d "$VENV" ]; then
  echo "Creating virtual environment..."
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install --quiet -r requirements.txt
fi

# Allow PORT as a shorthand alias
if [ -n "${PORT:-}" ]; then
  export TERMSITE_PORT="$PORT"
fi

exec "$VENV/bin/python" thismachine.py

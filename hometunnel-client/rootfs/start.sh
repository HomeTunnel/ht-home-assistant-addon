#!/usr/bin/env sh
set -eu

mkdir -p /data
mkdir -p /data/netbird
chmod 700 /data /data/netbird || true

python3 - <<'PY'
from pathlib import Path
import uuid

path = Path("/data/local_device_id")
if path.exists():
    value = path.read_text(encoding="utf-8").strip()
    if value:
        raise SystemExit(0)
path.write_text(str(uuid.uuid4()), encoding="utf-8")
PY

export HOST=0.0.0.0
export PORT=8099
export PROXY_HOST=0.0.0.0
export PROXY_PORT=8123
export PYTHONUNBUFFERED=1

python3 /opt/hometunnel/app.py --check-bind "${PROXY_HOST}" "${PROXY_PORT}"
python3 /opt/hometunnel/app.py --ha-proxy &
PROXY_PID=$!

cleanup() {
  kill "${PROXY_PID}" 2>/dev/null || true
}

trap cleanup EXIT INT TERM
sleep 1
if ! kill -0 "${PROXY_PID}" 2>/dev/null; then
  echo "ERROR: Home Assistant proxy failed to start on http://${PROXY_HOST}:${PROXY_PORT}" >&2
  wait "${PROXY_PID}"
  exit 1
fi

echo "HA proxy listening on http://${PROXY_HOST}:${PROXY_PORT}"
echo "UI listening on http://${HOST}:${PORT}"
exec python3 /opt/hometunnel/app.py

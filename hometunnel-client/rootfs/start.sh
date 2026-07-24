#!/usr/bin/env sh
set -eu

# --- Preflight: refuse to start on under-resourced hosts --------------------
# This addon runs several long-lived processes (UI, HA proxy, NetBird agent and
# the NetBird daemon). On <2 GB hosts (e.g. Raspberry Pi 3, 1 GB) that footprint
# lands on top of Home Assistant Core and can drive the whole system into swap,
# freezing the device. Home Assistant OS itself now requires a minimum of 2 GB.
# Rather than crash-loop and take the host down with us, detect this up front and
# exit cleanly with a clear message before spawning any of the real processes.
#
# The threshold is total RAM, not available RAM: total is deterministic and maps
# cleanly to hardware class, whereas available RAM fluctuates and would pass at a
# quiet moment then fail later. 1400 MB blocks 1 GB-class boards (which report
# ~950 MB) while still allowing genuine 2 GB devices (which report ~1.8-1.9 GB
# after firmware/GPU reservation), including the Raspberry Pi 4 2 GB.
python3 - <<'PY'
import json
import sys
import time
from pathlib import Path

MIN_MEMORY_MB = 1400
OPTIONS_PATH = Path("/data/options.json")


def option_enabled(name: str) -> bool:
    try:
        data = json.loads(OPTIONS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    value = data.get(name)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def meminfo_kb(key: str):
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if parts and parts[0].rstrip(":") == key and len(parts) >= 2:
                return int(parts[1])
    except (OSError, ValueError):
        return None
    return None


total_kb = meminfo_kb("MemTotal")
available_kb = meminfo_kb("MemAvailable")

if total_kb is None:
    print(
        "[preflight] WARNING: could not read MemTotal from /proc/meminfo; "
        "skipping RAM check.",
        file=sys.stderr,
        flush=True,
    )
    raise SystemExit(0)

total_mb = total_kb // 1024
available_mb = available_kb // 1024 if available_kb is not None else None
available_text = f"{available_mb} MB" if available_mb is not None else "unknown"

if total_mb >= MIN_MEMORY_MB:
    print(
        f"[preflight] RAM check passed: {total_mb} MB total "
        f"(available {available_text}, minimum {MIN_MEMORY_MB} MB).",
        flush=True,
    )
    raise SystemExit(0)

if option_enabled("allow_low_memory"):
    print(
        f"[preflight] WARNING: only {total_mb} MB total RAM (minimum "
        f"{MIN_MEMORY_MB} MB), but 'allow_low_memory' is set — starting anyway. "
        "The device may run out of memory and become unresponsive.",
        file=sys.stderr,
        flush=True,
    )
    raise SystemExit(0)

print(
    "\n".join(
        (
            "=======================================================================",
            "[preflight] HomeTunnel Client cannot start: insufficient memory.",
            f"[preflight]   Detected : {total_mb} MB total RAM (available {available_text})",
            f"[preflight]   Required : {MIN_MEMORY_MB} MB total RAM",
            "[preflight]",
            "[preflight] This 1 GB-class host (e.g. Raspberry Pi 3) does not have",
            "[preflight] enough memory to run this addon alongside Home Assistant Core",
            "[preflight] without risking the whole system running out of memory and",
            "[preflight] freezing. Home Assistant OS itself now requires 2 GB minimum.",
            "[preflight]",
            "[preflight] Recommended: move Home Assistant to a device with 2 GB+ RAM",
            "[preflight] (Raspberry Pi 4/5, Home Assistant Green/Yellow, or an x86 mini PC).",
            "[preflight]",
            "[preflight] To override at your own risk, set the addon option:",
            "[preflight]     allow_low_memory: true",
            "=======================================================================",
        )
    ),
    file=sys.stderr,
    flush=True,
)

# Exit non-zero so the addon is clearly marked failed rather than silently
# "running". Sleep briefly first so that with boot:auto + watchdog the restart
# loop stays gently paced (each attempt is near-zero memory, so it can no longer
# exhaust RAM or freeze the host) instead of hammering the supervisor.
time.sleep(10)
raise SystemExit(1)
PY

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

import asyncio
import hashlib
import contextlib
import fcntl
import ipaddress
import json
import logging
import os
import re
import signal
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import httpx
import uvicorn
import websockets
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response, StreamingResponse
from starlette.background import BackgroundTask

from network_context import (
    build_hometunnel_dns_hostname,
    build_network_context,
    collect_local_ipv4_context,
    normalize_home_assistant_access_mode as normalize_ha_access_mode,
)
from heartbeat_payload import build_heartbeat_payload

DATA_DIR = Path("/data")
STATE_PATH = DATA_DIR / "state.json"
OPTIONS_PATH = DATA_DIR / "options.json"
HA_PROXY_CACHE_PATH = DATA_DIR / "ha_proxy_cache.json"
LOCAL_DEVICE_ID_PATH = DATA_DIR / "local_device_id"
NETBIRD_AGENT_PID_PATH = DATA_DIR / "netbird-agent.pid"
NETBIRD_AGENT_START_LOCK_PATH = DATA_DIR / "netbird-agent-start.lock"
NETBIRD_UP_LOCK_PATH = DATA_DIR / "netbird-up.lock"
NETBIRD_DIR = DATA_DIR / "netbird"
NETBIRD_CONFIG_PATH = NETBIRD_DIR / "config.json"
NETBIRD_SOCKET_PATH = NETBIRD_DIR / "netbird.sock"
NETBIRD_DAEMON_PID_PATH = NETBIRD_DIR / "daemon.pid"
POLL_INTERVAL_SECONDS = 45
NETBIRD_RETRY_MIN_SECONDS = 5
NETBIRD_RETRY_MAX_SECONDS = 300
NETBIRD_UP_DEBOUNCE_SECONDS = 5
NETBIRD_READY_TIMEOUT_SECONDS = 20
NETBIRD_STATUS_CACHE_SECONDS = float(os.environ.get("NETBIRD_STATUS_CACHE_SECONDS") or "5")
ROUTE_REFRESH_CACHE_SECONDS = float(os.environ.get("ROUTE_REFRESH_CACHE_SECONDS") or "5")
PAIRING_SESSION_TTL_SECONDS = int(os.environ.get("PAIRING_SESSION_TTL_SECONDS") or "600")
HEARTBEAT_UNCHANGED_MIN_SECONDS = float(os.environ.get("HEARTBEAT_UNCHANGED_MIN_SECONDS") or "90")
HEALTH_REPORT_INTERVAL_SECONDS = float(os.environ.get("HEALTH_REPORT_INTERVAL_SECONDS") or "600")
LISTEN_HOST = os.environ.get("HOST") or "0.0.0.0"
LISTEN_PORT = int(os.environ.get("PORT") or "8099")
PROXY_LISTEN_HOST = os.environ.get("PROXY_HOST") or "0.0.0.0"
PROXY_LISTEN_PORT = int(os.environ.get("PROXY_PORT") or "8123")
PROXY_RESOLVE_INTERVAL_SECONDS = int(os.environ.get("HA_PROXY_RESOLVE_INTERVAL_SECONDS") or "60")
PROXY_CONNECT_TIMEOUT_SECONDS = float(os.environ.get("HA_PROXY_CONNECT_TIMEOUT_SECONDS") or "5")
PROXY_READ_TIMEOUT_SECONDS = float(os.environ.get("HA_PROXY_READ_TIMEOUT_SECONDS") or "180")
PROXY_WRITE_TIMEOUT_SECONDS = float(os.environ.get("HA_PROXY_WRITE_TIMEOUT_SECONDS") or "180")
PROXY_WS_OPEN_TIMEOUT_SECONDS = float(os.environ.get("HA_PROXY_WS_OPEN_TIMEOUT_SECONDS") or "10")
PROXY_WS_CLOSE_TIMEOUT_SECONDS = float(os.environ.get("HA_PROXY_WS_CLOSE_TIMEOUT_SECONDS") or "5")
SUPERVISOR_URL = (os.environ.get("SUPERVISOR_URL") or "http://supervisor").rstrip("/")
HA_TARGET_DEFAULT_PORT = int(os.environ.get("HA_TARGET_PORT") or "8123")
TARGET_DISCOVERY_TIMEOUT_SECONDS = float(os.environ.get("HA_TARGET_DISCOVERY_TIMEOUT_SECONDS") or "3")
TARGET_CHANGE_DEBOUNCE_SECONDS = float(os.environ.get("HA_TARGET_CHANGE_DEBOUNCE_SECONDS") or "15")
SAFE_RETRY_METHODS = {"GET", "HEAD", "OPTIONS"}
PROXY_STATUS_BUCKETS = ("/", "/auth/authorize", "/api/")
ACCESS_MODE_ROUTE = "route"
ACCESS_MODE_PROXY = "proxy"
ROUTE_MODE_HOST_ONLY = "host-only"
DNS_MODE_DEFAULT = "off"
DNS_MODE_ON_WARNING = "HomeTunnel DNS mode is on. Continuing startup without forcing HomeTunnel DNS control off."
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
WEBSOCKET_STRIP_HEADERS = HOP_BY_HOP_HEADERS | {
    "sec-websocket-accept",
    "sec-websocket-extensions",
    "sec-websocket-key",
    "sec-websocket-protocol",
    "sec-websocket-version",
}
SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-ha-access",
}
LOG = logging.getLogger("hometunnel")


SECRET_REDACTION = "***redacted***"
SECRET_FIELD_NAMES = {
    "authorization",
    "setupkey",
    "setup_key",
    "setupKey",
    "bindingid",
    "binding_id",
    "bindingId",
    "devicebindingid",
    "device_binding_id",
    "deviceBindingId",
    "devicetoken",
    "device_token",
    "deviceToken",
    "devicecode",
    "device_code",
    "deviceCode",
    "signedbindingtoken",
    "signed_binding_token",
    "signedBindingToken",
    "bindingtoken",
    "binding_token",
    "bindingToken",
    "signedbinding",
    "signed_binding",
    "signedBinding",
}
SECRET_TEXT_PATTERNS = (
    re.compile(r"(?i)(Authorization\s*[:=]\s*)(?:Bearer\s+|Token\s+)?[^\s,;]+"),
    re.compile(r"(?i)\b(Bearer|Token)\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)([?&](?:token|code|key|setup_key|setupKey|device_token|deviceToken|device_code|deviceCode)=)([^&#\s]+)"),
    re.compile(
        r"(?i)\b(setup[_ -]?key|device[_ -]?token|signed[_ -]?binding[_ -]?token|binding[_ -]?token|device[_ -]?binding[_ -]?id|binding[_ -]?id|device[_ -]?code|token)\b"
        r"(\s*[:=]\s*)"
        r"([^\s,;&\"'}\]]+)"
    ),
    re.compile(
        r"(?i)(['\"](?:setup[_-]?key|device[_-]?token|signed[_-]?binding[_-]?token|binding[_-]?token|device[_-]?binding[_-]?id|binding[_-]?id|device[_-]?code)['\"]\s*:\s*)"
        r"(['\"])(.*?)(['\"])"
    ),
)


class _RedactSecretsFilter(logging.Filter):
    def __init__(self) -> None:
        super().__init__()
        self._secret_cache_at = 0.0
        self._secret_cache: set[str] = set()

    def _state_secrets(self) -> set[str]:
        now = time.monotonic()
        if now - self._secret_cache_at < 5:
            return set(self._secret_cache)
        secrets: set[str] = set()
        try:
            payload = json.loads(STATE_PATH.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                for key in ("setup_key", "device_token"):
                    value = payload.get(key)
                    if isinstance(value, str) and value.strip():
                        secrets.add(value.strip())
                binding = payload.get("binding")
                if isinstance(binding, dict):
                    for key in ("binding_id", "device_binding_id", "signed_binding_token"):
                        value = binding.get(key)
                        if isinstance(value, str) and value.strip():
                            secrets.add(value.strip())
        except Exception:
            pass
        try:
            state_payload = globals().get("_state")
            if isinstance(state_payload, dict):
                for key in ("setup_key", "device_token"):
                    value = state_payload.get(key)
                    if isinstance(value, str) and value.strip():
                        secrets.add(value.strip())
                binding = state_payload.get("binding")
                if isinstance(binding, dict):
                    for key in ("binding_id", "device_binding_id", "signed_binding_token"):
                        value = binding.get(key)
                        if isinstance(value, str) and value.strip():
                            secrets.add(value.strip())
        except Exception:
            pass
        self._secret_cache = secrets
        self._secret_cache_at = now
        return set(secrets)

    def _redact_text(self, value: str) -> str:
        redacted = value
        for secret in self._state_secrets():
            redacted = redacted.replace(secret, SECRET_REDACTION)
        for pattern in SECRET_TEXT_PATTERNS:
            if pattern.groups >= 3:
                if pattern.groups >= 4:
                    redacted = pattern.sub(lambda match: f"{match.group(1)}{match.group(2)}{SECRET_REDACTION}{match.group(4)}", redacted)
                else:
                    redacted = pattern.sub(lambda match: f"{match.group(1)}{match.group(2)}{SECRET_REDACTION}", redacted)
            elif pattern.groups == 2:
                redacted = pattern.sub(lambda match: f"{match.group(1)}{SECRET_REDACTION}", redacted)
            else:
                redacted = pattern.sub(lambda match: f"{match.group(1)} {SECRET_REDACTION}", redacted)
        return redacted

    def _redact_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self._redact_text(value)
        if isinstance(value, dict):
            redacted: Dict[Any, Any] = {}
            for key, item in value.items():
                key_text = str(key)
                redacted[key] = SECRET_REDACTION if key_text in SECRET_FIELD_NAMES or key_text.lower() in SECRET_FIELD_NAMES else self._redact_value(item)
            return redacted
        if isinstance(value, tuple):
            return tuple(self._redact_value(item) for item in value)
        if isinstance(value, list):
            return [self._redact_value(item) for item in value]
        if isinstance(value, BaseException):
            try:
                value.args = tuple(self._redact_value(item) for item in value.args)
            except Exception:
                pass
        return value

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            try:
                message = record.getMessage()
            except Exception:
                message = str(record.msg)
            record.msg = self._redact_text(message)
            record.args = ()
            if record.exc_info and len(record.exc_info) >= 2 and isinstance(record.exc_info[1], BaseException):
                self._redact_value(record.exc_info[1])
            if record.exc_text:
                record.exc_text = self._redact_text(record.exc_text)
        except Exception:
            pass
        return True


_redact_secrets_filter = _RedactSecretsFilter()
LOG.addFilter(_redact_secrets_filter)
logging.getLogger().addFilter(_redact_secrets_filter)


def install_uvicorn_log_redaction() -> None:
    # uvicorn's access log records full request paths, including query strings
    # such as the Home Assistant OAuth callback (/?code=...&state=...). Attach
    # the redaction filter after uvicorn has configured its loggers.
    for logger_name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        logging.getLogger(logger_name).addFilter(_redact_secrets_filter)
_default_log_record_factory = logging.getLogRecordFactory()


def _redacting_log_record_factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
    record = _default_log_record_factory(*args, **kwargs)
    _redact_secrets_filter.filter(record)
    return record


logging.setLogRecordFactory(_redacting_log_record_factory)


def _collect_secret_values(value: Any) -> set[str]:
    secrets: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            if (key_text in SECRET_FIELD_NAMES or key_text.lower() in SECRET_FIELD_NAMES) and isinstance(item, str) and item.strip():
                secrets.add(item.strip())
            secrets.update(_collect_secret_values(item))
    elif isinstance(value, (list, tuple)):
        for item in value:
            secrets.update(_collect_secret_values(item))
    return secrets


def sanitize_for_display(value: Any, *, secret_source: Optional[Any] = None) -> Any:
    extra_secrets = _collect_secret_values(secret_source) if secret_source is not None else set()

    def sanitize_text(text: str) -> str:
        redacted = str(text)
        for secret in extra_secrets:
            if secret:
                redacted = redacted.replace(secret, SECRET_REDACTION)
        return _redact_secrets_filter._redact_text(redacted)

    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, dict):
        redacted: Dict[Any, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            redacted[key] = (
                SECRET_REDACTION
                if key_text in SECRET_FIELD_NAMES or key_text.lower() in SECRET_FIELD_NAMES
                else sanitize_for_display(item, secret_source=secret_source)
            )
        return redacted
    if isinstance(value, list):
        return [sanitize_for_display(item, secret_source=secret_source) for item in value]
    if isinstance(value, tuple):
        return tuple(sanitize_for_display(item, secret_source=secret_source) for item in value)
    if isinstance(value, BaseException):
        return sanitize_text(f"{value.__class__.__name__}: {value}")
    return value


def sanitize_error_text(value: Any, *, secret_source: Optional[Any] = None) -> str:
    text = sanitize_for_display(value, secret_source=secret_source)
    if not isinstance(text, str):
        text = stable_json_dumps(text)
    return text[:1024]


def sanitize_state_error_fields(state: Dict[str, Any]) -> Dict[str, Any]:
    for key in ("last_error", "heartbeat_error", "last_health_report_error", "local_status_detail"):
        if state.get(key) is not None:
            state[key] = sanitize_error_text(state.get(key), secret_source=state)
    if isinstance(state.get("last_health_result"), str):
        state["last_health_result"] = sanitize_error_text(state.get("last_health_result"), secret_source=state)
    for section_name in ("netbird", "route", "ha_proxy"):
        section = state.get(section_name)
        if isinstance(section, dict):
            for key in ("last_error", "raw", "local_ipv4_error"):
                if section.get(key) is not None:
                    section[key] = sanitize_error_text(section.get(key), secret_source=state)
    return state


def safe_binding_identifier(binding: Dict[str, Any]) -> Optional[str]:
    return (
        normalize_optional_string(binding.get("binding_id"))
        or normalize_optional_string(binding.get("device_binding_id"))
        or None
    )


def binding_token_present(binding: Dict[str, Any]) -> bool:
    return bool(normalize_optional_string(binding.get("signed_binding_token")))


def log_secret_marker(value: Any, *, missing: str = "<missing>") -> str:
    return SECRET_REDACTION if normalize_optional_string(value) else missing


def binding_last_update_at(binding: Dict[str, Any]) -> Optional[str]:
    return (
        normalize_optional_string(binding.get("persisted_at"))
        or normalize_optional_string(binding.get("received_at"))
        or normalize_optional_string(binding.get("presented_at"))
        or None
    )


def heartbeat_binding_cache_marker(binding: Dict[str, Any]) -> Dict[str, Any]:
    token = normalize_optional_string(binding.get("signed_binding_token"))
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest() if token else None
    return {
        "bindingId": safe_binding_identifier(binding),
        "bindingTokenPresent": bool(token),
        "bindingTokenHash": token_hash,
        "rotationCount": int(binding.get("rotation_count") or 0),
    }


def chmod_if_exists(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except Exception:
        pass


def ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    NETBIRD_DIR.mkdir(parents=True, exist_ok=True)
    for path in (DATA_DIR, NETBIRD_DIR):
        chmod_if_exists(path, 0o700)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json_file(path: Path, fallback: Any) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return fallback


_dns_mode_warning_logged = False


def normalize_dns_mode(value: Any) -> str:
    if value is False or value is None:
        return DNS_MODE_DEFAULT
    if isinstance(value, str):
        configured = value.strip().lower()
        if configured == "on":
            return "on"
        if configured in {"", "off"}:
            return DNS_MODE_DEFAULT
    return DNS_MODE_DEFAULT


def warn_if_dns_mode_on(options: Dict[str, Any]) -> bool:
    global _dns_mode_warning_logged
    value = options.get("dns_mode") if isinstance(options, dict) else None
    if not (isinstance(value, str) and value.strip().lower() == "on"):
        return False
    if not _dns_mode_warning_logged:
        LOG.warning(DNS_MODE_ON_WARNING)
        _dns_mode_warning_logged = True
    return True


def validate_dns_mode_options_file(path: Path = OPTIONS_PATH) -> bool:
    try:
        with path.open("r", encoding="utf-8") as handle:
            options = json.load(handle)
    except FileNotFoundError:
        options = {}
    except Exception:
        return False
    if not isinstance(options, dict):
        return False
    return warn_if_dns_mode_on(options)


def write_json_file(path: Path, value: Any) -> None:
    ensure_data_dir()
    if path == STATE_PATH and isinstance(value, dict):
        value = sanitize_state_error_fields(value)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.{uuid.uuid4().hex}.tmp")
    try:
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2)
        chmod_if_exists(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        except Exception:
            pass
    chmod_if_exists(path, 0o600)
    try:
        if path == STATE_PATH:
            _redact_secrets_filter._secret_cache_at = 0.0
    except Exception:
        pass


@contextlib.contextmanager
def exclusive_file_lock(path: Path):
    ensure_data_dir()
    with path.open("a+") as handle:
        chmod_if_exists(path, 0o600)
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def ensure_local_device_id() -> str:
    ensure_data_dir()
    try:
        existing = LOCAL_DEVICE_ID_PATH.read_text(encoding="utf-8").strip()
        if existing:
            return existing
    except Exception:
        pass

    local_device_id = str(uuid.uuid4())
    LOCAL_DEVICE_ID_PATH.write_text(local_device_id, encoding="utf-8")
    chmod_if_exists(LOCAL_DEVICE_ID_PATH, 0o600)
    return local_device_id


def normalize_optional_string(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def normalize_optional_json_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        try:
            return json.loads(json.dumps(value))
        except Exception:
            return None
    if isinstance(value, (str, int, float, bool)):
        return value
    text = str(value).strip()
    return text or None


def has_meaningful_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict)):
        return bool(value)
    return True


def unique_strings(values: list[Any]) -> list[str]:
    items: list[str] = []
    for value in values:
        text = normalize_optional_string(value)
        if text and text not in items:
            items.append(text)
    return items


def binding_device_label(device_id: Optional[str]) -> Optional[str]:
    value = normalize_optional_string(device_id)
    return f"ht-device-{value}" if value else None


def default_binding_state() -> Dict[str, Any]:
    return {
        "device_id": None,
        "home_id": None,
        "binding_id": None,
        "device_binding_id": None,
        "signed_binding_token": None,
        "expected_netbird_label": None,
        "netbird_labels": [],
        "setup_key_id": None,
        "setup_key_created_at": None,
        "setup_key_lineage": None,
        "received_at": None,
        "persisted_at": None,
        "presented_at": None,
        "rotation_count": 0,
        "status": "missing",
        "valid": False,
        "validation_error": "binding_missing",
        "portal_validation_error": None,
        "portal_validation_reported_at": None,
        "missing_fields": [],
        "netbird_label_apply_status": "pending",
    }


def default_pairing_session_state() -> Dict[str, Any]:
    return {
        "device_code": None,
        "user_code": None,
        "verification_url": None,
        "pairing_started_at": None,
        "pairing_expires_at": None,
        "pairing_status": None,
        "pairing_inflight": False,
        "poll_interval": 5,
    }


def default_device_auth_state() -> Dict[str, Any]:
    return {
        "device_code": None,
        "user_code": None,
        "verification_url": None,
        "expires_at": None,
        "poll_interval": 5,
        "status": None,
        "enroll_attempted": False,
        "enroll_attempted_at": None,
        "next_enroll_after": None,
    }


def load_options() -> Dict[str, Any]:
    options = read_json_file(OPTIONS_PATH, {})
    if not isinstance(options, dict):
        options = {}
    return {
        "hometunnel_url": str(options.get("hometunnel_url") or "https://my.hometunnel.io").strip().rstrip("/"),
        "home_assistant_url": str(options.get("home_assistant_url") or "").strip(),
        "home_assistant_target": str(options.get("home_assistant_target") or "").strip(),
        "always_on": bool(options.get("always_on", True)),
        "access_mode": str(options.get("access_mode") or "").strip().lower(),
        "log_level": str(options.get("log_level") or "info"),
        "allowed_routes": str(options.get("allowed_routes") or ""),
        "advertise_routes": str(options.get("advertise_routes") or ""),
        "dns_mode": normalize_dns_mode(options.get("dns_mode")),
        "expose_home_assistant_only": bool(options.get("expose_home_assistant_only", True)),
    }


def default_state() -> Dict[str, Any]:
    return {
        "local_device_id": ensure_local_device_id(),
        "device_auth": default_device_auth_state(),
        "pairing_session": default_pairing_session_state(),
        "pairing_state": "unpaired",
        "paired": False,
        "recovery_state": None,
        "local_status": None,
        "local_status_detail": None,
        "labels": [],
        "home_id": None,
        "device_id": None,
        "netbird_peer_id": None,
        "binding": default_binding_state(),
        "peer_name": None,
        "management_url": None,
        "setup_key": None,
        "device_token": None,
        "agent_running": False,
        "last_pair_check": None,
        "last_heartbeat_at": None,
        "last_heartbeat_result": None,
        "last_heartbeat_destination": None,
        "heartbeat_error": None,
        "last_health_check_at": None,
        "last_agent_report_at": None,
        "last_health_result": None,
        "last_health_report_error": None,
        "portal_base_url": None,
        "last_error": None,
        "netbird": {
            "connected": False,
            "peer_id": None,
            "wireguard_public_key": None,
            "peer_ip": None,
            "peer_name": None,
            "remote_peers": [],
            "raw": None,
        },
        "ha_proxy": {
            "selected_url": None,
            "selected_source": None,
            "last_resolved_at": None,
            "last_error": None,
        },
        "route": {
            "access_mode": None,
            "ha_access_mode": None,
            "route_mode": ROUTE_MODE_HOST_ONLY,
            "current_endpoint": None,
            "legacy_proxy_url": None,
            "configured_target": None,
            "target_host": None,
            "target_hostname": None,
            "resolved_target_hostname": None,
            "selected_target_ip": None,
            "target_ip": None,
            "resolved_target_ip": None,
            "effective_target_hostname": None,
            "target_port": HA_TARGET_DEFAULT_PORT,
            "target_scheme": "http",
            "target_type": None,
            "target_source": None,
            "local_tcp_8123_reachable": False,
            "health_status": "unknown",
            "target_reachable": False,
            "route_network": None,
            "desired_advertise_routes": None,
            "applied_advertise_routes": None,
            "local_ipv4_addresses": [],
            "local_ipv4_subnets": [],
            "local_ipv4_interfaces": [],
            "local_ipv4_source": None,
            "local_ipv4_error": None,
            "matching_local_subnets": [],
            "same_lan_detected": False,
            "exact_ip_conflict": False,
            "subnet_overlap": False,
            "local_bypass_recommended": False,
            "local_bypass_reason": None,
            "network_status": "waiting",
            "hometunnel_dns_hostname": None,
            "hometunnel_display_identity": None,
            "overlay_identity": None,
            "overlay_identity_basis": None,
            "effective_target_identity": None,
            "effective_target_cidr": None,
            "pending_target_host": None,
            "pending_target_hostname": None,
            "pending_target_ip": None,
            "pending_target_port": None,
            "pending_target_scheme": None,
            "pending_target_source": None,
            "pending_target_type": None,
            "pending_since": None,
            "needs_report": False,
            "last_resolved_at": None,
            "last_reconciled_at": None,
            "last_healthy_at": None,
            "last_change_at": None,
            "route_ids": [],
            "peer_group_ids": [],
            "policy_ids": [],
            "healthy": False,
            "last_error": None,
        },
    }


NON_RETRYABLE_RECOVERY_STATES = {
    "re_pair_required",
    "stale_binding",
    "device_credential_revoked",
    "peer_mismatch",
    "peer_conflict",
    "fatal_misconfiguration",
}


BINDING_FAILURE_CODES = {
    "binding_missing",
    "binding_token_missing",
    "binding_token_invalid",
    "binding_token_stale",
    "binding_claim_mismatch",
    "binding_not_found",
    "binding_revoked",
    "binding_rotated",
    "binding_home_mismatch",
    "binding_device_mismatch",
    "binding_required",
    "missing_binding",
    "invalid_binding",
    "binding_peer_mismatch",
    "binding_device_disabled",
    "binding_device_not_haos",
    "unauthorized",
    "invalid_token",
}


PEER_CONFLICT_CODES = {
    "peer_home_mismatch",
    "peer_identity_mismatch",
    "peer_conflict",
}


PEER_CONFLICT_MESSAGE = (
    "This NetBird peer is still linked to another HomeTunnel home or stale pairing. "
    "Reset pairing, remove the old HAOS device if needed, then pair again."
)


LOCAL_STATUS_MESSAGES = {
    "awaiting_approval": "Waiting for portal approval.",
    "approved_waiting_for_enroll": "Approval received; waiting for enrollment to finish.",
    "enrolled": "Enrollment is complete; waiting for NetBird transport to come up.",
    "transport_connected": "NetBird transport is connected.",
    "portal_trust_degraded": "NetBird transport is connected, but the portal heartbeat trust check failed. Local credentials were preserved.",
    "heartbeat_healthy": "Heartbeat is healthy.",
    "peer_id_missing": "NetBird peer id is missing; heartbeat is not sent.",
    "netbird_management_peer_id_missing": "Portal has not linked the NetBird management peer yet; heartbeat is not sent.",
    "missing_binding_id": "Binding id is missing; heartbeat is not sent. Re-pair is required.",
    "binding_material_missing": "Binding material is incomplete; re-pair is required.",
    "stale_binding": "The stored binding is stale. Re-pair is required.",
    "device_credential_revoked": "The device credential was revoked or rejected.",
    "peer_mismatch": "The local NetBird peer identity no longer matches the enrolled device.",
    "peer_conflict": PEER_CONFLICT_MESSAGE,
    "fatal_misconfiguration": "The portal rejected this HAOS device because its device type is invalid. Reset pairing and verify the portal device type.",
    "re_pair_required": "Re-pair is required before this device can be trusted again.",
    "heartbeat_failed_unknown": "Portal rejected the heartbeat with an unknown response. Local credentials were preserved; retry/backoff remains active.",
    "portal_persistence_failure": "The portal could not persist the latest heartbeat report.",
    "corrupted_state_reset": "Local state was corrupted and has been backed up. Re-pair if credentials are missing.",
}


def clear_setup_key_artifacts(state: Dict[str, Any]) -> None:
    state["setup_key"] = None
    state["binding"] = normalize_binding_state(
        {
            **state,
            "binding": merge_binding_sources(
                state.get("binding"),
                {},
                clear_keys={"setup_key_id", "setup_key_created_at", "setup_key_lineage"},
            ),
        }
    )


def classify_setup_key_join_failure(message: str) -> Optional[str]:
    text = str(message or "").strip().lower()
    if not text:
        return None
    if "setup key" not in text and "setup-key" not in text:
        return None
    if any(
        phrase in text
        for phrase in (
            "invalid",
            "expired",
            "revoked",
            "rejected",
            "already used",
            "already claimed",
            "claimed",
            "consumed",
            "disabled",
            "not found",
            "unauthorized",
            "forbidden",
        )
    ):
        return "setup_key_rejected"
    return None


def heartbeat_error_payload_fields(body: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    try:
        payload = json.loads(body)
    except Exception:
        return None, None, None
    if not isinstance(payload, dict):
        return None, None, None
    error = normalize_optional_string(first_present(payload, "error", "error_code", "errorCode"))
    code = normalize_optional_string(first_present(payload, "code"))
    message = normalize_optional_string(
        first_present(payload, "message", "detail", "details", "error_description", "errorDescription", "error_message", "errorMessage")
    )
    return error, code, sanitize_error_text(message, secret_source=payload) if message else None


def classify_heartbeat_failure(status: int, body: str) -> Dict[str, Any]:
    portal_error, portal_code, portal_message = heartbeat_error_payload_fields(body)
    machine_codes = [code for code in (portal_code, portal_error) if code]
    text = " ".join(part for part in (*machine_codes, portal_message, body) if part).lower()

    def result(
        *,
        recovery_state: Optional[str],
        error_code: str,
        message: str,
        clear_device_token: bool = False,
        clear_binding: bool = False,
        destructive: bool = False,
    ) -> Dict[str, Any]:
        return {
            "recovery_state": recovery_state,
            "error_code": error_code,
            "message": message,
            "clear_device_token": clear_device_token,
            "clear_binding": clear_binding,
            "destructive": destructive,
            "clear_setup_key": bool(
                recovery_state in NON_RETRYABLE_RECOVERY_STATES or error_code in BINDING_FAILURE_CODES
            ),
        }

    if 500 <= status <= 599:
        return result(
            recovery_state=None,
            error_code="portal_persistence_failure",
            message=portal_message or "Portal persistence failed.",
        )

    if status in (401, 403):
        selected_code = next((code for code in machine_codes if code in BINDING_FAILURE_CODES), None)
        if selected_code == "binding_token_stale":
            return result(
                recovery_state="stale_binding",
                error_code="binding_token_stale",
                message=portal_message or "The stored binding token is stale.",
                clear_binding=True,
                destructive=True,
            )
        if selected_code == "binding_peer_mismatch":
            return result(
                recovery_state="peer_mismatch",
                error_code="binding_peer_mismatch",
                message=portal_message or "The portal binding is assigned to a different NetBird peer. Reset pairing, then pair again.",
                clear_binding=True,
                destructive=True,
            )
        if selected_code == "binding_device_disabled":
            return result(
                recovery_state="re_pair_required",
                error_code="binding_device_disabled",
                message=portal_message or "The portal device was disabled or removed. Reset pairing, then pair again.",
                clear_binding=True,
                destructive=True,
            )
        if selected_code == "binding_device_not_haos":
            return result(
                recovery_state="fatal_misconfiguration",
                error_code="binding_device_not_haos",
                message=portal_message or "The portal device type is invalid for HAOS trusted heartbeat. Reset pairing and verify the portal device type.",
                clear_binding=True,
                destructive=True,
            )
        if selected_code:
            return result(
                recovery_state="re_pair_required",
                error_code=selected_code,
                message=portal_message or "Portal binding is required again. Reset pairing, then pair again.",
                clear_binding=True,
                destructive=True,
            )
        selected_credential_code = next(
            (
                code
                for code in machine_codes
                if code in {"device_credential_revoked", "device_credential_invalid"}
            ),
            None,
        )
        if selected_credential_code:
            return result(
                recovery_state="device_credential_revoked",
                error_code=selected_credential_code,
                message=portal_message or "The device credential was revoked or rejected.",
                clear_device_token=True,
                destructive=True,
            )
        return result(
            recovery_state="heartbeat_failed_unknown",
            error_code=f"heartbeat_http_{status}_unknown",
            message=portal_message or "Portal authorization failed with an unknown response. Local credentials were preserved.",
            destructive=False,
        )

    if status == 409:
        selected_peer_code = next((code for code in machine_codes if code in PEER_CONFLICT_CODES), None)
        if not selected_peer_code:
            selected_peer_code = next((code for code in PEER_CONFLICT_CODES if code in text), None)
        if selected_peer_code:
            return result(
                recovery_state="peer_conflict" if selected_peer_code in {"peer_home_mismatch", "peer_conflict"} else "peer_mismatch",
                error_code=selected_peer_code,
                message=portal_message or PEER_CONFLICT_MESSAGE,
                clear_binding=True,
                destructive=True,
            )
        return result(
            recovery_state="heartbeat_failed_unknown",
            error_code="heartbeat_http_409_unknown",
            message=portal_message or "Portal conflict response was unknown. Local credentials were preserved.",
            destructive=False,
        )

    if status == 404:
        return result(
            recovery_state="re_pair_required",
            error_code="heartbeat_http_404",
            message=portal_message or "Portal device heartbeat endpoint was not found for this enrollment.",
            clear_binding=True,
            destructive=True,
        )

    return result(
        recovery_state=None,
        error_code=f"heartbeat_http_{status}",
        message=portal_message or "Portal heartbeat failed.",
    )


CONNECTED_TRANSPORT_DESTRUCTIVE_HEARTBEAT_CODES = {
    "binding_revoked",
    "device_credential_revoked",
    "peer_identity_mismatch",
}


def should_degrade_connected_heartbeat_failure(status: Dict[str, Any], classification: Dict[str, Any]) -> bool:
    if not (bool(status.get("connected")) and normalize_optional_string(status.get("peer_id"))):
        return False
    return not bool(classification.get("destructive"))


def derive_local_status(state: Dict[str, Any]) -> tuple[str, str]:
    binding = normalize_binding_state(state)
    session = normalize_pairing_session_state(state)
    recovery_state = normalize_optional_string(state.get("recovery_state"))
    portal_validation_error = normalize_optional_string(binding.get("portal_validation_error"))
    heartbeat_error = normalize_optional_string(state.get("heartbeat_error"))
    health_report_error = normalize_optional_string(state.get("last_health_report_error"))
    last_error = normalize_optional_string(state.get("last_error"))
    transport_ready = bool(state.get("transport_ready"))
    binding_ready = bool(state.get("binding_ready"))
    paired = bool(state.get("paired"))

    if recovery_state in NON_RETRYABLE_RECOVERY_STATES:
        return recovery_state, LOCAL_STATUS_MESSAGES.get(recovery_state, recovery_state)
    if recovery_state == "heartbeat_failed_unknown":
        return recovery_state, LOCAL_STATUS_MESSAGES["heartbeat_failed_unknown"]
    if recovery_state == "portal_persistence_failure":
        return recovery_state, LOCAL_STATUS_MESSAGES["portal_persistence_failure"]
    if recovery_state == "corrupted_state_reset":
        return recovery_state, LOCAL_STATUS_MESSAGES["corrupted_state_reset"]

    for candidate in (heartbeat_error, health_report_error, last_error, portal_validation_error):
        if candidate == "heartbeat_auth_failed":
            return "portal_trust_degraded", LOCAL_STATUS_MESSAGES["portal_trust_degraded"]
        if candidate == "binding_token_stale":
            return "stale_binding", LOCAL_STATUS_MESSAGES["stale_binding"]
        if candidate in {
            "binding_required",
            "binding_home_mismatch",
            "binding_rotated",
            "binding_revoked",
            "missing_binding",
            "invalid_binding",
            "binding_missing",
            "binding_not_found",
            "binding_token_invalid",
            "binding_claim_mismatch",
            "binding_device_mismatch",
            "unauthorized",
            "invalid_token",
        }:
            return "re_pair_required", LOCAL_STATUS_MESSAGES["re_pair_required"]
        if candidate == "binding_device_disabled":
            return "re_pair_required", "The portal device was disabled or removed. Reset pairing, then pair again."
        if candidate == "binding_device_not_haos":
            return "fatal_misconfiguration", LOCAL_STATUS_MESSAGES["fatal_misconfiguration"]
        if candidate in {"device_credential_revoked", "device_credential_invalid"}:
            return "device_credential_revoked", LOCAL_STATUS_MESSAGES["device_credential_revoked"]
        if candidate == "peer_id_missing":
            return "peer_id_missing", LOCAL_STATUS_MESSAGES["peer_id_missing"]
        if candidate == "netbird_management_peer_id_missing":
            return "netbird_management_peer_id_missing", LOCAL_STATUS_MESSAGES["netbird_management_peer_id_missing"]
        if candidate == "missing_binding_id":
            return "missing_binding_id", LOCAL_STATUS_MESSAGES["missing_binding_id"]
        if candidate in {"peer_identity_mismatch", "binding_peer_mismatch"}:
            return "peer_mismatch", LOCAL_STATUS_MESSAGES["peer_mismatch"]
        if candidate in {"peer_home_mismatch", "peer_conflict"}:
            return "peer_conflict", LOCAL_STATUS_MESSAGES["peer_conflict"]
        if candidate in {"heartbeat_http_403_unknown", "heartbeat_http_409_unknown"}:
            return "heartbeat_failed_unknown", LOCAL_STATUS_MESSAGES["heartbeat_failed_unknown"]
        if candidate == "portal_persistence_failure":
            return "portal_persistence_failure", LOCAL_STATUS_MESSAGES["portal_persistence_failure"]

    if session.get("pairing_inflight") or normalize_optional_string(session.get("pairing_status")) in {"starting", "pending"}:
        return "awaiting_approval", LOCAL_STATUS_MESSAGES["awaiting_approval"]
    if normalize_optional_string(session.get("pairing_status")) == "approved" and not normalize_optional_string(state.get("device_token")):
        return "approved_waiting_for_enroll", LOCAL_STATUS_MESSAGES["approved_waiting_for_enroll"]
    if paired and binding.get("status") in {"missing", "partial", "invalid"} and any(
        field in {"binding_id", "device_binding_id"} for field in (binding.get("missing_fields") or [])
    ):
        return "binding_material_missing", LOCAL_STATUS_MESSAGES["binding_material_missing"]
    if binding.get("status") == "invalid" and portal_validation_error:
        if portal_validation_error == "binding_token_stale":
            return "stale_binding", LOCAL_STATUS_MESSAGES["stale_binding"]
        return "re_pair_required", LOCAL_STATUS_MESSAGES["re_pair_required"]
    if paired and binding_ready and transport_ready:
        if normalize_optional_string(state.get("last_heartbeat_at")) and not heartbeat_error and not health_report_error:
            return "heartbeat_healthy", LOCAL_STATUS_MESSAGES["heartbeat_healthy"]
        return "transport_connected", LOCAL_STATUS_MESSAGES["transport_connected"]
    if paired and binding_ready:
        return "enrolled", LOCAL_STATUS_MESSAGES["enrolled"]
    if binding.get("valid") and not paired:
        return "re_pair_required", LOCAL_STATUS_MESSAGES["re_pair_required"]
    if any(normalize_optional_string(state.get(key)) for key in ("device_id", "home_id", "management_url")):
        return "re_pair_required", LOCAL_STATUS_MESSAGES["re_pair_required"]
    return "awaiting_approval", LOCAL_STATUS_MESSAGES["awaiting_approval"]


PAIRING_TRANSITIONS = {
    "unpaired": {"unpaired", "pending", "approved", "connecting", "connected"},
    "pending": {"pending", "approved", "connecting", "connected", "unpaired"},
    "approved": {"approved", "connecting", "connected", "unpaired"},
    "connecting": {"connecting", "connected", "unpaired"},
    "connected": {"connected", "connecting", "unpaired"},
    "error": {"error", "unpaired", "pending", "approved", "connecting", "connected"},
}


def derive_pairing_state(state: Dict[str, Any]) -> str:
    session = normalize_pairing_session_state(state)
    recovery_state = normalize_optional_string(state.get("recovery_state"))
    pairing_status = normalize_optional_string(session.get("pairing_status"))
    last_error = normalize_optional_string(state.get("last_error"))
    transport_ready = bool(state.get("transport_ready"))
    binding_ready = bool(state.get("binding_ready"))
    paired = bool(state.get("paired"))

    if recovery_state or pairing_status == "error" or last_error in {"re_pair_required", "state_file_corrupted"}:
        return "error"
    if transport_ready and binding_ready and normalize_optional_string(state.get("last_heartbeat_at")):
        return "connected"
    if (paired and binding_ready) or (paired and not transport_ready):
        return "connecting"
    if pairing_status in {"approved", "already_enrolled"} and not paired:
        return "approved"
    if session.get("pairing_inflight") or pairing_status in {"starting", "pending"}:
        return "pending"
    return "unpaired"


def valid_pairing_transition(previous: Optional[str], next_state: str) -> bool:
    prev = previous or "unpaired"
    if next_state in {"error", "unpaired"}:
        return True
    return next_state in PAIRING_TRANSITIONS.get(prev, {"unpaired", "pending", "approved", "connecting", "connected"})


_state_lock = threading.Lock()
_state = default_state()
_stop_event = threading.Event()
_options = load_options()
_pairing_start_lock = threading.Lock()
_netbird_status_lock = threading.Lock()
_netbird_status_cache: Dict[str, Any] = {"value": None, "at": 0.0}
_route_refresh_lock = threading.Lock()
_route_refresh_cache: Dict[str, Any] = {"key": None, "value": None, "at": 0.0}
_heartbeat_lock = threading.Lock()
_heartbeat_cache: Dict[str, Any] = {"fingerprint": None, "sent_at": 0.0}
_proxy_diag_lock = threading.Lock()
_proxy_diagnostics: Dict[str, Any] = {
    "last_upstream_status": {
        bucket: {
            "status_code": None,
            "source": None,
            "upstream_url": None,
            "location": None,
            "observed_at": None,
            "error": None,
        }
        for bucket in PROXY_STATUS_BUCKETS
    },
    "last_401": {
        "path": None,
        "source": None,
        "upstream_url": None,
        "location": None,
        "observed_at": None,
        "error": None,
    },
}


def load_state() -> None:
    global _state
    loaded: Any = {}
    state_file_corrupted = False
    try:
        if STATE_PATH.exists():
            loaded = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        state_file_corrupted = True
        backup_path = STATE_PATH.with_name(f"{STATE_PATH.name}.corrupted-{int(time.time())}")
        try:
            STATE_PATH.replace(backup_path)
            LOG.warning("state file corrupted, backed up and reset backup=%s", backup_path)
        except Exception as exc:
            LOG.warning("state file corrupted, backup failed and reset error=%s", exc)
        loaded = {}
    except Exception as exc:
        LOG.warning("state file unreadable, reset error=%s", exc)
        loaded = {}
    merged = default_state()
    if isinstance(loaded, dict):
        merged.update(loaded)
        if isinstance(loaded.get("binding"), dict):
            merged["binding"].update(loaded["binding"])
        if isinstance(loaded.get("device_auth"), dict):
            merged["device_auth"].update(loaded["device_auth"])
        if isinstance(loaded.get("pairing_session"), dict):
            merged["pairing_session"].update(loaded["pairing_session"])
        if isinstance(loaded.get("netbird"), dict):
            merged["netbird"].update(loaded["netbird"])
        if isinstance(loaded.get("ha_proxy"), dict):
            merged["ha_proxy"].update(loaded["ha_proxy"])
        if isinstance(loaded.get("route"), dict):
            merged["route"].update(loaded["route"])
    if state_file_corrupted:
        merged["recovery_state"] = "corrupted_state_reset"
        merged["last_error"] = "state_file_corrupted"
    device_auth = dict(merged.get("device_auth") or {})
    if (
        bool(device_auth.get("enroll_attempted"))
        and normalize_optional_string(device_auth.get("status")) in {"approved", "already_enrolled"}
        and not bool(merged.get("paired"))
        and not binding_ready_from_state(merged)
        and not normalize_optional_string(merged.get("device_token"))
    ):
        device_auth["enroll_attempted"] = False
        device_auth["next_enroll_after"] = None
        merged["device_auth"] = device_auth
    merged["local_device_id"] = ensure_local_device_id()
    merged = status_view_from_state(merged, load_options())
    sanitize_state_error_fields(merged)
    _state = merged
    loaded_binding = normalize_binding_state(_state)
    LOG.info(
        "agent state loaded source=disk home_id_present=%s device_id_present=%s binding_id_present=%s token_present=%s setup_key_present=%s binding_status=%s recovery_state=%s last_error=%s",
        bool(normalize_optional_string(_state.get("home_id"))),
        bool(normalize_optional_string(_state.get("device_id"))),
        bool(safe_binding_identifier(loaded_binding)),
        bool(normalize_optional_string(_state.get("device_token"))),
        bool(normalize_optional_string(_state.get("setup_key"))),
        loaded_binding.get("status") or "missing",
        normalize_optional_string(_state.get("recovery_state")) or "<none>",
        normalize_optional_string(_state.get("last_error")) or "<none>",
    )
    write_json_file(STATE_PATH, _state)


def stable_json_dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def clone_json(value: Any) -> Any:
    return json.loads(json.dumps(value))


def parse_datetime_utc(value: Any) -> Optional[datetime]:
    text = normalize_optional_string(value)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text)
    except Exception:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def pairing_deadline_iso(started_at: Any, expires_at: Any = None) -> Optional[str]:
    started = parse_datetime_utc(started_at)
    explicit_expiry = parse_datetime_utc(expires_at)
    capped_expiry = started + timedelta(seconds=PAIRING_SESSION_TTL_SECONDS) if started else None
    if explicit_expiry and capped_expiry:
        return min(explicit_expiry, capped_expiry).isoformat()
    if explicit_expiry:
        return explicit_expiry.isoformat()
    if capped_expiry:
        return capped_expiry.isoformat()
    return None


def pairing_session_is_expired(session: Dict[str, Any], *, now: Optional[datetime] = None) -> bool:
    expires_at = parse_datetime_utc(session.get("pairing_expires_at"))
    if expires_at is None:
        return False
    current_time = now or datetime.now(timezone.utc)
    return expires_at <= current_time


def pairing_session_remaining_seconds(session: Dict[str, Any], *, now: Optional[datetime] = None) -> Optional[int]:
    expires_at = parse_datetime_utc(session.get("pairing_expires_at"))
    if expires_at is None:
        return None
    current_time = now or datetime.now(timezone.utc)
    remaining = int((expires_at - current_time).total_seconds())
    return max(0, remaining)


def normalize_pairing_session_state(state: Dict[str, Any]) -> Dict[str, Any]:
    session = default_pairing_session_state()
    raw_session = dict(state.get("pairing_session") or {})
    device_auth = dict(state.get("device_auth") or {})
    session["device_code"] = normalize_optional_string(raw_session.get("device_code")) or normalize_optional_string(device_auth.get("device_code"))
    session["user_code"] = normalize_optional_string(raw_session.get("user_code")) or normalize_optional_string(device_auth.get("user_code"))
    session["verification_url"] = normalize_optional_string(raw_session.get("verification_url")) or normalize_optional_string(
        device_auth.get("verification_url")
    )
    started_at = normalize_optional_string(raw_session.get("pairing_started_at"))
    expires_at = normalize_optional_string(raw_session.get("pairing_expires_at")) or normalize_optional_string(device_auth.get("expires_at"))
    if not started_at and expires_at:
        expires_dt = parse_datetime_utc(expires_at)
        if expires_dt is not None:
            started_at = (expires_dt - timedelta(seconds=PAIRING_SESSION_TTL_SECONDS)).isoformat()
    session["pairing_started_at"] = started_at
    session["pairing_expires_at"] = pairing_deadline_iso(started_at, expires_at)
    session["pairing_status"] = normalize_optional_string(raw_session.get("pairing_status")) or normalize_optional_string(device_auth.get("status"))
    try:
        session["poll_interval"] = max(1, int(raw_session.get("poll_interval") or device_auth.get("poll_interval") or 5))
    except Exception:
        session["poll_interval"] = 5
    session["pairing_inflight"] = bool(raw_session.get("pairing_inflight"))
    if pairing_session_is_expired(session):
        session["pairing_inflight"] = False
        if session["device_code"] or session["pairing_status"] in {"starting", "pending", "approved", "already_enrolled"}:
            session["pairing_status"] = "expired"
    return session


def apply_pairing_session_to_state(state: Dict[str, Any], session: Dict[str, Any]) -> None:
    existing_device_auth = dict(state.get("device_auth") or {})
    normalized_session = normalize_pairing_session_state({"pairing_session": session, "device_auth": existing_device_auth})
    state["pairing_session"] = normalized_session
    state["device_auth"] = {
        "device_code": normalized_session.get("device_code"),
        "user_code": normalized_session.get("user_code"),
        "verification_url": normalized_session.get("verification_url"),
        "expires_at": normalized_session.get("pairing_expires_at"),
        "poll_interval": normalized_session.get("poll_interval") or 5,
        "status": normalized_session.get("pairing_status"),
        "enroll_attempted": bool(existing_device_auth.get("enroll_attempted")),
        "enroll_attempted_at": normalize_optional_string(existing_device_auth.get("enroll_attempted_at")),
        "next_enroll_after": normalize_optional_string(existing_device_auth.get("next_enroll_after")),
    }


def update_pairing_session_state(state: Dict[str, Any], updates: Dict[str, Any], *, replace: bool = False) -> None:
    session = default_pairing_session_state() if replace else normalize_pairing_session_state(state)
    session.update(updates)
    apply_pairing_session_to_state(state, session)


def clear_pairing_session_state(state: Dict[str, Any]) -> None:
    state["pairing_session"] = default_pairing_session_state()
    state["device_auth"] = {
        **default_device_auth_state(),
        "enroll_attempted": bool(dict(state.get("device_auth") or {}).get("enroll_attempted")),
        "enroll_attempted_at": normalize_optional_string(dict(state.get("device_auth") or {}).get("enroll_attempted_at")),
        "next_enroll_after": normalize_optional_string(dict(state.get("device_auth") or {}).get("next_enroll_after")),
    }


def pairing_session_is_reusable(session: Dict[str, Any]) -> bool:
    return bool(
        normalize_optional_string(session.get("device_code"))
        and normalize_optional_string(session.get("user_code"))
        and normalize_optional_string(session.get("verification_url"))
        and not pairing_session_is_expired(session)
    )


def pairing_start_gate(state: Dict[str, Any], session: Optional[Dict[str, Any]] = None) -> tuple[bool, Optional[str]]:
    current_session = session or normalize_pairing_session_state(state)
    if bool(state.get("transport_ready")):
        return False, "transport_ready"
    if bool(state.get("binding_ready")) or bool(state.get("paired")) or any(
        state.get(key) for key in ("device_id", "home_id", "management_url", "setup_key", "device_token")
    ):
        return False, "already_enrolled"
    if bool(current_session.get("pairing_inflight")):
        return False, "pairing_inflight"
    if pairing_session_is_reusable(current_session):
        return False, "active_pairing_session"
    return True, None


def should_clear_pairing_session_for_state(state: Dict[str, Any]) -> bool:
    session = normalize_pairing_session_state(state)
    if session.get("pairing_status") not in {"approved", "already_enrolled"}:
        return False
    return bool(state.get("transport_ready")) or bool(state.get("binding_ready"))


def update_state(mutator) -> bool:
    with _state_lock:
        previous_pairing_state = derive_pairing_state(status_view_from_state(_state, _options))
        before = stable_json_dumps(_state)
        mutator(_state)
        next_state = status_view_from_state(_state, _options)
        sanitize_state_error_fields(next_state)
        next_pairing_state = str(next_state.get("pairing_state") or "unpaired")
        if not valid_pairing_transition(previous_pairing_state, next_pairing_state):
            LOG.warning("invalid_pairing_transition prev=%s next=%s", previous_pairing_state, next_pairing_state)
        _state.clear()
        _state.update(next_state)
        after = stable_json_dumps(_state)
        if after == before:
            return False
        write_json_file(STATE_PATH, _state)
        return True


def read_state_snapshot() -> Dict[str, Any]:
    state = read_json_file(STATE_PATH, default_state())
    if not isinstance(state, dict):
        state = default_state()
    return state


def update_proxy_runtime_state(
    selected_url: Optional[str],
    selected_source: Optional[str],
    last_resolved_at: Optional[str],
    last_error: Optional[str],
) -> None:
    latest_state = read_state_snapshot()
    proxy_state = dict(latest_state.get("ha_proxy") or {})
    proxy_state.update(
        {
            "selected_url": selected_url,
            "selected_source": selected_source,
            "last_resolved_at": last_resolved_at,
            "last_error": last_error,
        }
    )
    latest_state["ha_proxy"] = proxy_state
    write_json_file(STATE_PATH, latest_state)


def raw_query_string(scope: Dict[str, Any]) -> str:
    query = scope.get("query_string", b"")
    if isinstance(query, bytes):
        return query.decode("latin-1")
    return str(query or "")


def proxy_status_bucket(path: str) -> Optional[str]:
    if path == "/":
        return "/"
    if path == "/auth/authorize":
        return "/auth/authorize"
    if path == "/api" or path.startswith("/api/"):
        return "/api/"
    return None


def record_proxy_status(
    path: str,
    *,
    status_code: Optional[int],
    source: str,
    upstream_url: Optional[str] = None,
    location: Optional[str] = None,
    error: Optional[str] = None,
) -> None:
    bucket = proxy_status_bucket(path)
    if bucket is None:
        return
    payload = {
        "status_code": status_code,
        "source": source,
        "upstream_url": upstream_url,
        "location": location,
        "observed_at": now_iso(),
        "error": error,
    }
    with _proxy_diag_lock:
        _proxy_diagnostics["last_upstream_status"][bucket] = payload
        if status_code == 401:
            _proxy_diagnostics["last_401"] = {
                "path": bucket,
                "source": source,
                "upstream_url": upstream_url,
                "location": location,
                "observed_at": payload["observed_at"],
                "error": error,
            }


def proxy_diagnostics_snapshot() -> Dict[str, Any]:
    with _proxy_diag_lock:
        return json.loads(json.dumps(_proxy_diagnostics))


def first_present(obj: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = obj.get(key)
        if value is not None:
            return value
    return None


def is_auth_approved(status: Optional[str]) -> bool:
    return str(status or "").lower() in {"approved", "authorized", "authenticated", "complete"}


def has_onboarding_payload(payload: Any) -> bool:
    onboarding = find_value(payload, {"onboarding"})
    return isinstance(onboarding, dict) and bool(onboarding)


def run_command(args: list[str], timeout_seconds: int = 20) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        return completed.returncode, completed.stdout.strip(), completed.stderr.strip()
    except Exception as exc:
        return 1, "", sanitize_error_text(exc)


def netbird_binary_path() -> Optional[str]:
    return shutil.which("netbird")


def find_value(obj: Any, key_names: set[str]) -> Optional[Any]:
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in key_names:
                return value
            nested = find_value(value, key_names)
            if nested is not None:
                return nested
    if isinstance(obj, list):
        for item in obj:
            nested = find_value(item, key_names)
            if nested is not None:
                return nested
    return None


def first_present_string(obj: Dict[str, Any], *keys: str) -> Optional[str]:
    value = first_present(obj, *keys)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def normalize_netbird_ip(value: Any) -> Optional[str]:
    text = str(value or "").strip()
    if not text:
        return None
    if "/" in text:
        text = text.split("/", 1)[0].strip()
    unwrapped = text[1:-1] if text.startswith("[") and text.endswith("]") else text
    try:
        ipaddress.ip_address(unwrapped)
    except ValueError:
        return text or None
    return unwrapped


def normalize_netbird_peer(entry: Any) -> Optional[Dict[str, Optional[str]]]:
    if not isinstance(entry, dict):
        return None
    peer_id = first_present_string(entry, "peer_id", "peerId", "id", "ID")
    wireguard_public_key = first_present_string(entry, "wireguard_public_key", "wireguardPublicKey", "publicKey", "public_key", "pubKey")
    peer_ip = normalize_netbird_ip(first_present(entry, "peer_ip", "peerIp", "ip", "netbirdIp", "netbird_ip", "address"))
    peer_name = first_present_string(entry, "peer_name", "peerName", "fqdn", "name", "hostname")
    if not peer_id and not wireguard_public_key and not peer_ip and not peer_name:
        return None
    return {"peer_id": peer_id, "wireguard_public_key": wireguard_public_key, "peer_ip": peer_ip, "peer_name": peer_name}


def netbird_peer_sources(parsed: Dict[str, Any]) -> list[Dict[str, Any]]:
    sources: list[Dict[str, Any]] = [parsed]
    for key in ("self", "peer", "localPeer", "local_peer", "thisPeer", "this_peer", "currentPeer", "current_peer", "netbird", "status"):
        value = parsed.get(key)
        if isinstance(value, dict):
            sources.append(value)
    return sources


def extract_netbird_self_peer(parsed: Dict[str, Any]) -> Dict[str, Optional[str]]:
    for source in netbird_peer_sources(parsed):
        normalized = normalize_netbird_peer(source)
        if normalized:
            return normalized
    return {"peer_id": None, "peer_ip": None, "peer_name": None}


def flatten_dict_items(value: Any) -> list[Dict[str, Any]]:
    items: list[Dict[str, Any]] = []
    if isinstance(value, dict):
        items.append(value)
        for child in value.values():
            items.extend(flatten_dict_items(child))
    elif isinstance(value, list):
        for child in value:
            items.extend(flatten_dict_items(child))
    return items


def peer_connected_value(entry: Dict[str, Any]) -> bool:
    connected_raw = first_present(entry, "connected", "isConnected", "online")
    if connected_raw is not None:
        return bool(connected_raw)
    state = str(first_present(entry, "connectionState", "peerState", "state", "status") or "").strip().lower()
    return state in {"connected", "online", "active"}


def extract_connected_remote_peers(parsed: Dict[str, Any], self_peer: Dict[str, Optional[str]]) -> list[Dict[str, Optional[str]]]:
    remote_sections = []
    for key in ("peers", "remotePeers", "remote_peers"):
        value = parsed.get(key)
        if value is not None:
            remote_sections.append(value)

    connected_peers: list[Dict[str, Optional[str]]] = []
    seen: set[tuple[Optional[str], Optional[str], Optional[str]]] = set()
    for section in remote_sections:
        for candidate in flatten_dict_items(section):
            normalized = normalize_netbird_peer(candidate)
            if not normalized or not peer_connected_value(candidate):
                continue
            identity = (
                normalized.get("peer_id"),
                normalized.get("peer_ip"),
                normalized.get("peer_name"),
            )
            if identity == (
                self_peer.get("peer_id"),
                self_peer.get("peer_ip"),
                self_peer.get("peer_name"),
            ):
                continue
            if identity in seen:
                continue
            seen.add(identity)
            connected_peers.append(normalized)
    return connected_peers


def extract_netbird_connected(parsed: Dict[str, Any], self_peer: Dict[str, Optional[str]], text_hint: str = "") -> bool:
    sources = netbird_peer_sources(parsed)
    explicit_false = False
    positive_markers = ("connected", "ready", "online", "active")
    negative_markers = ("disconnected", "disconnecting", "offline", "stopped", "error", "failed")
    for source in sources:
        direct = first_present(source, "connected", "isConnected", "online")
        if direct is not None:
            if bool(direct):
                return True
            explicit_false = True
        for key in (
            "management_state",
            "managementState",
            "management_connection_state",
            "managementConnectionState",
            "signal_state",
            "signalState",
            "peer_state",
            "peerState",
            "connection_state",
            "connectionState",
            "status",
            "state",
        ):
            value = first_present_string(source, key)
            if not value:
                continue
            lowered = value.lower()
            if any(marker in lowered for marker in positive_markers):
                return True
            if any(marker in lowered for marker in negative_markers):
                explicit_false = True
    hint = text_hint.lower()
    if "connected to the management service stream" in hint:
        return True
    if "management service" in hint and "connected" in hint:
        return True
    if self_peer.get("peer_ip") and not explicit_false:
        return True
    return False


def invalidate_runtime_caches(reason: str) -> None:
    with _netbird_status_lock:
        _netbird_status_cache["value"] = None
        _netbird_status_cache["at"] = 0.0
    with _route_refresh_lock:
        _route_refresh_cache["key"] = None
        _route_refresh_cache["value"] = None
        _route_refresh_cache["at"] = 0.0
    with _heartbeat_lock:
        _heartbeat_cache["fingerprint"] = None
        _heartbeat_cache["sent_at"] = 0.0
    LOG.debug("runtime caches invalidated reason=%s", reason)


def collect_netbird_status() -> Dict[str, Any]:
    now_monotonic = time.monotonic()
    with _netbird_status_lock:
        cached = _netbird_status_cache.get("value")
        cached_at = float(_netbird_status_cache.get("at") or 0.0)
        if cached is not None and now_monotonic - cached_at < NETBIRD_STATUS_CACHE_SECONDS:
            LOG.debug("netbird status refresh skipped cached age_seconds=%.1f", now_monotonic - cached_at)
            return clone_json(cached)

    if not netbird_binary_path():
        value = {
            "connected": False,
            "peer_id": None,
            "wireguard_public_key": None,
            "peer_ip": None,
            "peer_name": None,
            "remote_peers": [],
            "raw": "netbird binary not found",
        }
        with _netbird_status_lock:
            _netbird_status_cache["value"] = clone_json(value)
            _netbird_status_cache["at"] = now_monotonic
        return value
    rc, out, err = run_command(netbird_command("status", "--json"), timeout_seconds=10)
    if rc == 0 and out:
        try:
            parsed = json.loads(out)
            raw_text = stable_json_dumps(parsed if isinstance(parsed, dict) else {"raw": parsed})
            self_peer = extract_netbird_self_peer(parsed if isinstance(parsed, dict) else {})
            connected = extract_netbird_connected(parsed if isinstance(parsed, dict) else {}, self_peer, raw_text)
            remote_peers = extract_connected_remote_peers(parsed if isinstance(parsed, dict) else {}, self_peer) if isinstance(parsed, dict) else []
            LOG.debug(
                "netbird self identity connected=%s peer_id=%s peer_name=%s peer_ip=%s connected_remote_peers=%s",
                connected,
                self_peer.get("peer_id") or "<unknown>",
                self_peer.get("peer_name") or "<unknown>",
                self_peer.get("peer_ip") or "<unknown>",
                remote_peers or [],
            )
            value = {
                "connected": connected,
                "peer_id": self_peer.get("peer_id"),
                "wireguard_public_key": self_peer.get("wireguard_public_key"),
                "peer_ip": self_peer.get("peer_ip"),
                "peer_name": self_peer.get("peer_name"),
                "remote_peers": remote_peers,
                "raw": parsed,
            }
            with _netbird_status_lock:
                _netbird_status_cache["value"] = clone_json(value)
                _netbird_status_cache["at"] = now_monotonic
            return value
        except Exception:
            pass

    rc, out, err = run_command(netbird_command("status"), timeout_seconds=10)
    text = out or err
    lowered_text = text.lower()
    connected = (
        "connected to the management service stream" in lowered_text
        or ("management service" in lowered_text and "connected" in lowered_text)
        or ("connected" in lowered_text and "disconnected" not in lowered_text)
    )
    peer_ip = None
    for token in text.replace(",", " ").split():
        normalized = normalize_netbird_ip(token)
        if normalized:
            peer_ip = normalized
            break
    LOG.debug(
        "netbird self identity peer_id=%s peer_name=%s peer_ip=%s connected_remote_peers=%s",
        "<unknown>",
        "<unknown>",
        peer_ip or "<unknown>",
        [],
    )
    value = {"connected": connected, "peer_id": None, "wireguard_public_key": None, "peer_ip": peer_ip, "peer_name": None, "remote_peers": [], "raw": text}
    with _netbird_status_lock:
        _netbird_status_cache["value"] = clone_json(value)
        _netbird_status_cache["at"] = now_monotonic
    return value


def request_json(
    method: str,
    url: str,
    payload: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout_seconds: int = 20,
) -> Dict[str, Any]:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, method=method.upper(), data=body)
    req.add_header("Accept", "application/json")
    if payload is not None:
        req.add_header("Content-Type", "application/json")
    if headers:
        for key, value in headers.items():
            req.add_header(key, value)
    with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
        raw = response.read().decode("utf-8")
        return json.loads(raw) if raw else {}


def upstream_path(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        safe_query = urllib.parse.urlencode(
            [
                (
                    key,
                    "***redacted***"
                    if key in {"device_code", "deviceCode", "setup_key", "setupKey", "device_token", "deviceToken"}
                    or key.lower() in {"token", "code", "key"}
                    else value,
                )
                for key, value in query
            ]
        )
        return f"{path}?{safe_query}"
    return path


def sanitize_destination_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    base = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    return f"{base}{upstream_path(url)}"


def url_origin(url: str) -> Optional[str]:
    parsed = urllib.parse.urlsplit(str(url or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def portal_base_candidates(state: Optional[Dict[str, Any]], options: Dict[str, Any]) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add_candidate(raw: Optional[str], reason: str) -> None:
        value = str(raw or "").strip().rstrip("/")
        if not value or value in seen:
            return
        seen.add(value)
        candidates.append((value, reason))

    add_candidate((state or {}).get("portal_base_url"), "persisted_successful_portal_base")
    add_candidate(options.get("hometunnel_url"), "configured_hometunnel_url")
    return candidates


def remember_portal_base(base_url: str) -> None:
    normalized = str(base_url or "").strip().rstrip("/")
    if not normalized:
        return
    update_state(lambda state: state.update({"portal_base_url": normalized}))


def should_retry_portal_base(exc: Exception) -> bool:
    return not isinstance(exc, urllib.error.HTTPError)


def effective_dns_mode(options: Dict[str, Any]) -> str:
    return normalize_dns_mode(options.get("dns_mode") if isinstance(options, dict) else None)


def read_resolver_diagnostics() -> Dict[str, Any]:
    path = Path("/etc/resolv.conf")
    raw = ""
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return {
            "path": str(path),
            "read_error": str(exc),
            "raw": None,
            "nameservers": [],
            "search_domains": [],
            "options": [],
        }

    nameservers: list[str] = []
    search_domains: list[str] = []
    options_list: list[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        keyword = parts[0].lower()
        values = parts[1:]
        if keyword == "nameserver":
            nameservers.extend(values)
        elif keyword == "search":
            search_domains.extend(values)
        elif keyword == "options":
            options_list.extend(values)
    return {
        "path": str(path),
        "raw": raw,
        "nameservers": nameservers,
        "search_domains": search_domains,
        "options": options_list,
    }


def socket_resolution_probe(host: str, port: int = 443) -> Dict[str, Any]:
    result: Dict[str, Any] = {"host": host, "port": port}
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        addresses: list[str] = []
        for item in infos:
            sockaddr = item[4]
            if isinstance(sockaddr, tuple) and sockaddr:
                candidate = str(sockaddr[0])
                if candidate not in addresses:
                    addresses.append(candidate)
        result["getaddrinfo"] = {"ok": True, "addresses": addresses}
    except Exception as exc:
        result["getaddrinfo"] = {"ok": False, "error": str(exc)}
    try:
        host_info = socket.gethostbyname_ex(host)
        result["gethostbyname_ex"] = {"ok": True, "result": list(host_info)}
    except Exception as exc:
        result["gethostbyname_ex"] = {"ok": False, "error": str(exc)}
    return result


def urllib_probe(url: str) -> Dict[str, Any]:
    safe_url = sanitize_destination_url(url)
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=5) as response:
            return {"url": safe_url, "ok": True, "status": response.status}
    except urllib.error.HTTPError as exc:
        return {"url": safe_url, "ok": True, "status": exc.code, "error": str(exc)}
    except Exception as exc:
        return {"url": safe_url, "ok": False, "error": str(exc)}


def heartbeat_runtime_phase(state: Dict[str, Any]) -> str:
    if bool((state.get("netbird") or {}).get("connected")) or bool(state.get("agent_running")):
        return "after_netbird_connected"
    return "before_netbird_connected"


def heartbeat_transport_diagnostics(state: Optional[Dict[str, Any]] = None, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    state_snapshot = state or read_state_snapshot()
    latest_options = options or load_options()
    intended_base = str(latest_options.get("hometunnel_url") or "").strip().rstrip("/")
    intended_host = urllib.parse.urlsplit(intended_base).hostname
    last_attempt_url = str(state_snapshot.get("last_heartbeat_destination") or "").strip()
    last_attempt_host = urllib.parse.urlsplit(last_attempt_url).hostname if last_attempt_url else None
    candidate_bases = [
        {"base_url": base_url, "reason": reason}
        for base_url, reason in portal_base_candidates(state_snapshot, latest_options)
    ]
    hosts_to_probe: list[str] = []
    for host in (
        intended_host,
        urllib.parse.urlsplit(str((state_snapshot.get("portal_base_url") or ""))).hostname,
        urllib.parse.urlsplit(str((state_snapshot.get("management_url") or ""))).hostname,
        "openai.com",
    ):
        if host and host not in hosts_to_probe:
            hosts_to_probe.append(host)
    return {
        "intended_heartbeat_base_url": intended_base or None,
        "intended_heartbeat_host": intended_host,
        "last_heartbeat_destination": sanitize_destination_url(last_attempt_url) if last_attempt_url else None,
        "last_heartbeat_destination_host": last_attempt_host,
        "configured_hometunnel_url": latest_options.get("hometunnel_url"),
        "configured_dns_mode": latest_options.get("dns_mode"),
        "effective_dns_mode": effective_dns_mode(latest_options),
        "persisted_portal_base_url": state_snapshot.get("portal_base_url"),
        "management_url": state_snapshot.get("management_url"),
        "management_origin": url_origin(str(state_snapshot.get("management_url") or "")),
        "netbird_dns_phase": heartbeat_runtime_phase(state_snapshot),
        "netbird_connected": bool((state_snapshot.get("netbird") or {}).get("connected")),
        "agent_running": bool(state_snapshot.get("agent_running")),
        "resolver": read_resolver_diagnostics(),
        "candidate_bases": candidate_bases,
        "resolution": [socket_resolution_probe(host) for host in hosts_to_probe],
        "urllib_probe": urllib_probe(last_attempt_url or intended_base) if (last_attempt_url or intended_base) else None,
        "heartbeat_error": state_snapshot.get("heartbeat_error"),
    }


def portal_request_json(
    method: str,
    path: str,
    *,
    state: Optional[Dict[str, Any]],
    options: Dict[str, Any],
    payload: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout_seconds: int = 20,
    purpose: str,
) -> tuple[Dict[str, Any], str, str]:
    candidates = portal_base_candidates(state, options)
    if not candidates:
        raise RuntimeError("missing portal base url")

    last_exc: Optional[Exception] = None
    last_url = ""
    configured_base = str(options.get("hometunnel_url") or "").strip().rstrip("/") or "<unset>"
    for index, (base_url, reason) in enumerate(candidates):
        url = f"{base_url}{path}"
        host = urllib.parse.urlsplit(url).hostname or "<unknown>"
        fallback_attempted = False
        LOG.info(
            "%s destination url=%s host=%s chosen_base_url=%s reason=%s configured_hometunnel_url=%s fallback=%s attempt=%s/%s",
            purpose,
            sanitize_destination_url(url),
            host,
            base_url,
            reason,
            configured_base,
            index > 0,
            index + 1,
            len(candidates),
        )
        try:
            response = request_json(
                method,
                url,
                payload,
                headers=headers,
                timeout_seconds=timeout_seconds,
            )
            remember_portal_base(base_url)
            return response, url, base_url
        except Exception as exc:
            fallback_attempted = index < len(candidates) - 1 and should_retry_portal_base(exc)
            LOG.warning(
                "%s transport failure host=%s base_url=%s reason=%s configured_hometunnel_url=%s error=%s fallback_attempted=%s",
                purpose,
                host,
                base_url,
                reason,
                configured_base,
                exc,
                fallback_attempted,
            )
            last_exc = exc
            last_url = url
            if not fallback_attempted:
                break
    if last_exc is None:
        raise RuntimeError(f"{purpose} failed without exception")
    setattr(last_exc, "_hometunnel_url", last_url)
    raise last_exc


def safe_body_preview(body: str) -> str:
    if not body:
        return ""
    try:
        parsed = json.loads(body)
    except Exception:
        return sanitize_error_text(body)

    def redact(value: Any) -> Any:
        if isinstance(value, dict):
            redacted: Dict[str, Any] = {}
            for key, item in value.items():
                if key in {"setup_key", "setupKey", "device_token", "deviceToken", "device_code", "deviceCode"}:
                    redacted[key] = "***redacted***"
                elif key in {
                    "binding_id",
                    "bindingId",
                    "device_binding_id",
                    "deviceBindingId",
                    "signed_binding_token",
                    "signedBindingToken",
                    "binding_token",
                    "bindingToken",
                }:
                    redacted[key] = "***redacted***"
                else:
                    redacted[key] = redact(item)
            return redacted
        if isinstance(value, list):
            return [redact(item) for item in value]
        return value

    return sanitize_error_text(json.dumps(redact(parsed)))


def read_http_error_body(exc: urllib.error.HTTPError) -> str:
    try:
        return exc.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


def log_upstream_result(url: str, status: Optional[int], body: str) -> None:
    LOG.warning(
        "upstream request path=%s status=%s body=%s",
        upstream_path(url),
        status if status is not None else "n/a",
        safe_body_preview(body),
    )


def upstream_error_details(body: str) -> tuple[Optional[str], Optional[str]]:
    try:
        payload = json.loads(body)
    except Exception:
        return None, None
    if not isinstance(payload, dict):
        return None, None
    code = normalize_optional_string(first_present(payload, "code", "error", "error_code", "errorCode"))
    message = normalize_optional_string(
        first_present(payload, "message", "detail", "details", "error_description", "errorDescription", "error_message", "errorMessage")
    )
    return code, sanitize_error_text(message, secret_source=payload) if message else None


def map_upstream_error(prefix: str, url: str, exc: urllib.error.HTTPError) -> JSONResponse:
    status = exc.code
    body = read_http_error_body(exc)
    path = upstream_path(url)
    log_upstream_result(url, status, body)

    if status == 404:
        return JSONResponse(
            {
                "ok": False,
                "code": f"{prefix}_http_404",
                "upstream_url": path,
                "upstream_status": 404,
                "message": "Upstream endpoint not found. Backend route missing or misconfigured.",
            },
            status_code=424,
        )
    if status in (401, 403):
        return JSONResponse(
            {
                "ok": False,
                "code": "not_authorized",
                "upstream_url": path,
                "upstream_status": status,
                "message": "Upstream authorization failed.",
            },
            status_code=401,
        )
    if status == 429:
        return JSONResponse(
            {
                "ok": False,
                "code": "rate_limited",
                "upstream_url": path,
                "upstream_status": 429,
                "message": "Upstream rate limit reached.",
            },
            status_code=429,
        )
    if 500 <= status <= 599:
        return JSONResponse(
            {
                "ok": False,
                "code": "upstream_error",
                "upstream_url": path,
                "upstream_status": status,
                "message": "Upstream service error.",
            },
            status_code=502,
        )
    return JSONResponse(
        {
            "ok": False,
            "code": f"{prefix}_http_{status}",
            "upstream_url": path,
            "upstream_status": status,
            "message": "Upstream request failed.",
        },
        status_code=status,
    )


def enroll_http_error_response(url: str, status: int, body: str) -> JSONResponse:
    path = upstream_path(url)
    portal_code, portal_message = upstream_error_details(body)
    return JSONResponse(
        {
            "ok": False,
            "code": portal_code or f"enroll_http_{status}",
            "upstream_url": path,
            "upstream_status": status,
            "message": sanitize_error_text(portal_message or ("Upstream service error." if 500 <= status <= 599 else "Upstream request failed.")),
        },
        status_code=status,
    )


def connectivity_error_response(url: str, exc: Exception) -> JSONResponse:
    safe_error = sanitize_error_text(exc)
    LOG.warning("upstream connectivity path=%s error=%s", upstream_path(url), safe_error)
    return JSONResponse(
        {
            "ok": False,
            "code": "connectivity_failed",
            "message": safe_error,
        },
        status_code=502,
    )


def build_device_name() -> str:
    hostname = socket.gethostname().strip()
    return hostname or "home-assistant"


def normalize_access_mode(value: str) -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in {ACCESS_MODE_ROUTE, ACCESS_MODE_PROXY} else ""


def effective_access_mode(options: Dict[str, Any], state: Dict[str, Any]) -> str:
    configured = normalize_access_mode(str(options.get("access_mode") or ""))
    if configured:
        return configured
    if state.get("paired") or state.get("device_id") or state.get("home_id"):
        return ACCESS_MODE_PROXY
    return ACCESS_MODE_ROUTE


def effective_home_assistant_access_mode(route_state: Dict[str, Any]) -> str:
    return normalize_ha_access_mode(route_state.get("ha_access_mode")) or "direct_ip"


def log_heartbeat_payload(payload: Dict[str, Any]) -> None:
    serialized_payload = json.dumps(payload)
    LOG.info(
        "heartbeat payload size_bytes=%s top_level_keys=%s ha_keys=%s peer_keys=%s health_keys=%s route_keys=%s network_keys=%s target_keys=%s target_observation_keys=%s",
        len(serialized_payload.encode("utf-8")),
        sorted(payload.keys()),
        sorted((payload.get("ha") or {}).keys()),
        sorted((payload.get("peer") or {}).keys()),
        sorted((payload.get("health") or {}).keys()),
        sorted((payload.get("route") or {}).keys()),
        sorted((payload.get("network") or {}).keys()),
        sorted((payload.get("target") or {}).keys()),
        sorted((payload.get("targetObservation") or {}).keys()),
    )


def split_routes(raw_routes: str) -> list[str]:
    parts: list[str] = []
    for item in str(raw_routes or "").split(","):
        route = item.strip()
        if route and route not in parts:
            parts.append(route)
    return parts


def format_routes(routes: list[str]) -> str:
    return ",".join(route for route in routes if route)


def desired_advertise_routes(state: Dict[str, Any], options: Dict[str, Any]) -> str:
    route_state = dict(state.get("route") or {})
    access_mode = effective_access_mode(options, state)
    auto_route = str(route_state.get("route_network") or "").strip() if access_mode == ACCESS_MODE_ROUTE else ""
    if bool(options.get("expose_home_assistant_only", True)):
        return auto_route
    return format_routes([*([auto_route] if auto_route else []), *split_routes(str(options.get("advertise_routes") or ""))])


def format_netbird_up_error(message: str) -> str:
    text = sanitize_error_text(str(message or "").strip() or "failed")
    if "--advertise-routes" in text:
        return (
            "unsupported NetBird route-advertisement flag detected; "
            "hometunnel-portal now creates routes and policies through the NetBird control plane, "
            f"so the HAOS client only enrolls the peer locally ({text})"
        )
    return text


def route_url(scheme: str, host: str, port: int) -> str:
    safe_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return urllib.parse.urlunsplit((scheme, f"{safe_host}:{port}", "", "", ""))


def supervisor_headers() -> Dict[str, str]:
    token = str(os.environ.get("SUPERVISOR_TOKEN") or "").strip()
    return {"Authorization": f"Bearer {token}"} if token else {}


def supervisor_request_json(path: str) -> Dict[str, Any]:
    headers = supervisor_headers()
    if not headers:
        raise RuntimeError("SUPERVISOR_TOKEN missing")
    return request_json("GET", f"{SUPERVISOR_URL}{path}", headers=headers, timeout_seconds=int(TARGET_DISCOVERY_TIMEOUT_SECONDS) + 1)


def core_service_scheme() -> str:
    try:
        info = supervisor_request_json("/core/info")
    except Exception:
        return "http"
    return "https" if bool(info.get("ssl")) else "http"


def parse_target_input(value: str, default_port: int = HA_TARGET_DEFAULT_PORT, default_scheme: str = "http") -> Optional[Dict[str, Any]]:
    raw = str(value or "").strip()
    if not raw:
        return None
    parsed = urllib.parse.urlsplit(raw if "://" in raw else f"{default_scheme}://{raw}")
    host = parsed.hostname or ""
    if not host:
        return None
    return {
        "raw": raw,
        "host": host,
        "port": int(parsed.port or default_port),
        "scheme": parsed.scheme or default_scheme,
        "target_type": "ip" if is_ip_address(host) else "hostname",
        "target_hostname": None if is_ip_address(host) else host,
    }


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value))
        return True
    except Exception:
        return False


def is_valid_route_target_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(str(value))
    except Exception:
        return False
    return not (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified)


def route_network_for_ip(value: str) -> Optional[str]:
    try:
        ip = ipaddress.ip_address(str(value))
    except Exception:
        return None
    return f"{ip}/{32 if ip.version == 4 else 128}"


def extract_ip_from_cidr(value: Any) -> Optional[str]:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return str(ipaddress.ip_interface(raw).ip)
    except Exception:
        host = raw.split("/", 1)[0]
        return host if is_ip_address(host) else None


def resolve_host_ips(host: str, port: int) -> list[str]:
    if is_ip_address(host):
        return [host] if is_valid_route_target_ip(host) else []
    resolved: list[str] = []
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except Exception:
        return []
    for family, _, _, _, sockaddr in infos:
        candidate = sockaddr[0] if isinstance(sockaddr, tuple) and sockaddr else None
        if not candidate or not is_valid_route_target_ip(candidate):
            continue
        if family == socket.AF_INET:
            resolved.insert(0, candidate) if candidate not in resolved else None
        elif candidate not in resolved:
            resolved.append(candidate)
    return resolved


def tcp_target_reachable(host: str, port: int) -> tuple[bool, Optional[str]]:
    try:
        with socket.create_connection((host, port), timeout=TARGET_DISCOVERY_TIMEOUT_SECONDS):
            return True, None
    except Exception as exc:
        return False, sanitize_error_text(exc)


def health_status_for_target(target_reachable: bool, has_target: bool) -> str:
    if target_reachable:
        return "healthy"
    if has_target:
        return "degraded"
    return "unresolved"


def local_network_context() -> Dict[str, Any]:
    try:
        return collect_local_ipv4_context()
    except Exception as exc:
        LOG.warning("local network context collection failed error=%s", exc)
        return {
            "source": "error",
            "local_ipv4_addresses": [],
            "local_ipv4_subnets": [],
            "local_ipv4_interfaces": [],
            "error": sanitize_error_text(exc),
        }


def route_network_context(
    state: Dict[str, Any],
    route_state: Dict[str, Any],
    options: Dict[str, Any],
    *,
    local_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    context = dict(local_context or local_network_context())
    network = build_network_context(
        local_ipv4_addresses=context.get("local_ipv4_addresses") or [],
        local_ipv4_subnets=context.get("local_ipv4_subnets") or [],
        target_ip=route_state.get("resolved_target_ip") or route_state.get("target_ip"),
        target_hostname=route_state.get("target_hostname"),
        resolved_target_ip=route_state.get("resolved_target_ip") or route_state.get("target_ip"),
        resolved_target_hostname=route_state.get("resolved_target_hostname") or route_state.get("target_hostname"),
        ha_access_mode=effective_home_assistant_access_mode(route_state),
        route_mode=route_state.get("route_mode"),
        device_id=normalize_optional_string(state.get("device_id")),
        home_id=normalize_optional_string(state.get("home_id")),
        target_source=route_state.get("target_source"),
    )
    network.update(
        {
            "local_ipv4_interfaces": context.get("local_ipv4_interfaces") or [],
            "local_ipv4_source": context.get("source"),
            "local_ipv4_error": context.get("error"),
        }
    )
    return network


def select_supervisor_host_target() -> tuple[Optional[Dict[str, Any]], Optional[str]]:
    scheme = core_service_scheme()
    network_info = supervisor_request_json("/network/info")
    interfaces = network_info.get("interfaces") if isinstance(network_info, dict) else None
    if not isinstance(interfaces, list):
        return None, "network_interfaces_missing"
    preferred = sorted(
        [item for item in interfaces if isinstance(item, dict)],
        key=lambda item: (not bool(item.get("primary")), not bool(item.get("connected")), item.get("interface") or ""),
    )
    for item in preferred:
        if not bool(item.get("enabled", True)):
            continue
        ipv4 = item.get("ipv4") if isinstance(item.get("ipv4"), dict) else {}
        ipv6 = item.get("ipv6") if isinstance(item.get("ipv6"), dict) else {}
        for family, payload in (("ipv4", ipv4), ("ipv6", ipv6)):
            ip_value = extract_ip_from_cidr(payload.get("ip_address")) if isinstance(payload, dict) else None
            if not ip_value or not is_valid_route_target_ip(ip_value):
                continue
            return (
                {
                    "raw": ip_value,
                    "host": ip_value,
                    "port": HA_TARGET_DEFAULT_PORT,
                    "scheme": scheme,
                    "target_type": family,
                    "target_hostname": None,
                },
                None,
            )
    return None, "no_primary_interface_ip"


def select_core_config_target() -> tuple[Optional[Dict[str, Any]], Optional[str]]:
    scheme = core_service_scheme()
    config = supervisor_request_json("/core/api/config")
    for key in ("internal_url", "external_url"):
        candidate = parse_target_input(str(config.get(key) or ""), default_port=HA_TARGET_DEFAULT_PORT, default_scheme=scheme)
        if candidate:
            return candidate, None
    return None, "core_urls_missing"


def resolve_route_target(options: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    explicit_value = str(options.get("home_assistant_target") or options.get("home_assistant_url") or "").strip()
    cached_route = dict(state.get("route") or {})
    cached_value = str(cached_route.get("target_hostname") or cached_route.get("target_ip") or cached_route.get("target_host") or "").strip()
    try:
        supervisor_candidate, supervisor_error = select_supervisor_host_target()
    except Exception as exc:
        supervisor_candidate, supervisor_error = None, str(exc)
    try:
        core_candidate, core_error = select_core_config_target()
    except Exception as exc:
        core_candidate, core_error = None, str(exc)

    # Order matters: the first candidate that resolves is selected (see the loop
    # below). Prefer sources that describe THIS device's own Home Assistant --
    # explicit config, then the Supervisor's own primary interface, then Core's
    # configured URL -- before falling back to cached state or the shared
    # "homeassistant.local" mDNS name. That generic name is NOT unique: on a LAN
    # with more than one HAOS device it can resolve to a *different* device, which
    # would make this addon target the wrong Home Assistant. It must therefore
    # only ever be a last resort, never win over the local device's own address.
    candidates: list[tuple[str, Optional[Dict[str, Any]], Optional[str]]] = [
        ("configured_target", parse_target_input(explicit_value), None if explicit_value else "not_configured"),
        ("supervisor_network", supervisor_candidate, supervisor_error),
        ("core_config", core_candidate, core_error),
        ("last_known_good", parse_target_input(cached_value), None if cached_value else "no_cached_target"),
        ("homeassistant_local", parse_target_input("http://homeassistant.local:8123"), None),
    ]

    errors: list[str] = []
    selected: Optional[Dict[str, Any]] = None
    for source, candidate, candidate_error in candidates:
        if not candidate:
            if candidate_error:
                errors.append(f"{source}:{candidate_error}")
            continue
        resolved_ips = resolve_host_ips(candidate["host"], int(candidate["port"]))
        if not resolved_ips:
            errors.append(f"{source}:unresolved")
            continue
        selected_ip = resolved_ips[0]
        reachable, reachability_error = tcp_target_reachable(selected_ip, HA_TARGET_DEFAULT_PORT)
        selected = {
            "source": source,
            "configured_target": explicit_value or None,
            "target_host": candidate["host"],
            "target_hostname": candidate.get("target_hostname"),
            "resolved_target_hostname": candidate.get("target_hostname"),
            "selected_target_ip": candidate["host"] if is_ip_address(candidate["host"]) else None,
            "target_ip": selected_ip,
            "resolved_target_ip": selected_ip,
            "target_port": HA_TARGET_DEFAULT_PORT,
            "target_scheme": str(candidate["scheme"] or "http"),
            "target_type": candidate["target_type"],
            "local_tcp_8123_reachable": reachable,
            "target_reachable": reachable,
            "health_status": health_status_for_target(reachable, True),
            "route_network": route_network_for_ip(selected_ip),
            "effective_target_cidr": route_network_for_ip(selected_ip),
            "current_endpoint": route_url(str(candidate["scheme"] or "http"), selected_ip, HA_TARGET_DEFAULT_PORT),
            "last_error": None if reachable else (reachability_error or "tcp_probe_failed"),
        }
        break

    if selected is None:
        return {
            "configured_target": explicit_value or None,
            "target_host": None,
            "target_hostname": None,
            "resolved_target_hostname": None,
            "selected_target_ip": None,
            "target_ip": None,
            "resolved_target_ip": None,
            "target_port": HA_TARGET_DEFAULT_PORT,
            "target_scheme": "http",
            "target_type": None,
            "target_source": None,
            "local_tcp_8123_reachable": False,
            "health_status": "unresolved",
            "target_reachable": False,
            "route_network": None,
            "effective_target_cidr": None,
            "current_endpoint": None,
            "last_error": ";".join(errors[-4:]) if errors else "unresolved",
        }

    selected["target_source"] = selected.pop("source")
    return selected


def extract_route_status_from_response(response: Dict[str, Any]) -> Dict[str, Any]:
    route_ids = find_value(response, {"route_ids", "routeIds"}) if isinstance(response, dict) else None
    peer_group_ids = find_value(response, {"peer_group_ids", "peerGroupIds", "group_ids", "groupIds"}) if isinstance(response, dict) else None
    policy_ids = find_value(response, {"policy_ids", "policyIds"}) if isinstance(response, dict) else None
    applied_advertise_routes = find_value(response, {"applied_advertise_routes", "appliedAdvertiseRoutes"}) if isinstance(response, dict) else None

    def as_list(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item) for item in value if str(item or "").strip()]
        text = str(value or "").strip()
        return [text] if text else []

    return {
        "route_ids": as_list(route_ids),
        "peer_group_ids": as_list(peer_group_ids),
        "policy_ids": as_list(policy_ids),
        "applied_advertise_routes": str(applied_advertise_routes or "").strip() or None,
        "healthy": bool(first_present(response, "healthy", "ok")),
        "last_error": first_present(response, "error", "message"),
    }


def extract_home_access_mode_from_response(response: Dict[str, Any]) -> Optional[str]:
    if not isinstance(response, dict):
        return None
    home_access = response.get("home_access")
    if not isinstance(home_access, dict):
        return None
    primary_resource = home_access.get("primary_resource")
    if isinstance(primary_resource, dict):
        return normalize_ha_access_mode(
            first_present(primary_resource, "accessMode", "access_mode")
        ) or None
    return normalize_ha_access_mode(first_present(home_access, "accessMode", "access_mode")) or None


def route_state_material_view(route_state: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: value
        for key, value in route_state.items()
        if key not in {"last_resolved_at", "last_healthy_at", "last_change_at"}
    }


def heartbeat_fingerprint(payload: Dict[str, Any], state: Optional[Dict[str, Any]] = None) -> str:
    comparable = clone_json(payload)
    comparable["netbirdLastSeen"] = None
    if isinstance(comparable.get("health"), dict):
        comparable["health"]["reported_at"] = None
        comparable["health"]["last_health_check_at"] = None
        comparable["health"]["last_agent_report_at"] = None
    if isinstance(comparable.get("ha"), dict):
        comparable["ha"]["last_health_check_at"] = None
        comparable["ha"]["lastHealthCheckAt"] = None
        comparable["ha"]["last_agent_report_at"] = None
        comparable["ha"]["lastAgentReportAt"] = None
    if state is not None:
        comparable["binding"] = heartbeat_binding_cache_marker(normalize_binding_state(state))
        comparable.pop("bindingToken", None)
        comparable.pop("binding_token", None)
    else:
        token = normalize_optional_string(comparable.pop("bindingToken", None))
        if token is None:
            token = normalize_optional_string(comparable.pop("binding_token", None))
        if token is not None:
            comparable["bindingTokenPresent"] = True
            comparable["bindingTokenHash"] = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return stable_json_dumps(comparable)


def extract_portal_netbird_peer_id(payload: Any) -> Optional[str]:
    if not isinstance(payload, dict):
        return None
    return normalize_optional_string(
        first_present(payload, "netbird_peer_id", "netbirdPeerId")
    )


def persist_portal_device_config(config: Dict[str, Any], options: Dict[str, Any], resolved_base: Optional[str] = None) -> Optional[str]:
    netbird_peer_id = extract_portal_netbird_peer_id(config)

    def apply_config(current: Dict[str, Any]) -> None:
        if netbird_peer_id:
            current["netbird_peer_id"] = netbird_peer_id
        binding = config.get("binding")
        if isinstance(binding, dict):
            current["binding"] = normalize_binding_state(
                {
                    **current,
                    "binding": merge_binding_sources(current.get("binding"), binding, clear_portal_validation=True),
                }
            )
        if resolved_base:
            current["portal_base_url"] = resolved_base
        current["last_error"] = None if netbird_peer_id else current.get("last_error")

    update_state(apply_config)
    return netbird_peer_id


def fetch_device_config(state: Dict[str, Any], options: Dict[str, Any]) -> Optional[str]:
    device_token = normalize_optional_string(state.get("device_token"))
    device_id = normalize_optional_string(state.get("device_id"))
    if not device_token or not device_id:
        return None
    config_path = f"/api/devices/{urllib.parse.quote(str(device_id))}/config"
    response, _url, resolved_base = portal_request_json(
        "GET",
        config_path,
        state=state,
        options=options,
        headers={"Authorization": f"Bearer {device_token}"},
        purpose="device config",
    )
    returned_device_id = normalize_optional_string(first_present(response, "deviceId", "device_id"))
    if returned_device_id and returned_device_id != device_id:
        raise RuntimeError("device config response device mismatch")
    return persist_portal_device_config(response, options, resolved_base)


def refresh_route_runtime_state(options: Optional[Dict[str, Any]] = None, status: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    latest_options = options or load_options()
    state = read_state_snapshot()
    local_context = local_network_context()
    cache_key = stable_json_dumps(
        {
            "options": latest_options,
            "status": {
                "connected": bool(status.get("connected")) if status else None,
                "peer_id": status.get("peer_id") if status else None,
                "peer_ip": status.get("peer_ip") if status else None,
                "peer_name": status.get("peer_name") if status else None,
            },
            "route": state.get("route") or {},
            "local_network": {
                "addresses": local_context.get("local_ipv4_addresses") or [],
                "subnets": local_context.get("local_ipv4_subnets") or [],
                "source": local_context.get("source"),
            },
        }
    )
    now_monotonic = time.monotonic()
    with _route_refresh_lock:
        cached_key = _route_refresh_cache.get("key")
        cached_value = _route_refresh_cache.get("value")
        cached_at = float(_route_refresh_cache.get("at") or 0.0)
        if cached_value is not None and cached_key == cache_key and now_monotonic - cached_at < ROUTE_REFRESH_CACHE_SECONDS:
            LOG.debug("ha route refresh skipped cached age_seconds=%.1f", now_monotonic - cached_at)
            return clone_json(cached_value)

    access_mode = effective_access_mode(latest_options, state)
    discovered = resolve_route_target(latest_options, state)
    route_state = dict(state.get("route") or {})
    now = now_iso()
    legacy_proxy_url = None
    if status and status.get("peer_ip"):
        legacy_proxy_url = route_url("http", str(status["peer_ip"]), PROXY_LISTEN_PORT)
    elif route_state.get("legacy_proxy_url"):
        legacy_proxy_url = str(route_state.get("legacy_proxy_url"))
    current_identity = (
        str(route_state.get("resolved_target_ip") or route_state.get("target_ip") or ""),
        int(route_state.get("target_port") or HA_TARGET_DEFAULT_PORT),
        str(route_state.get("target_scheme") or "http"),
    )
    discovered_identity = (
        str(discovered.get("resolved_target_ip") or discovered.get("target_ip") or ""),
        int(discovered.get("target_port") or HA_TARGET_DEFAULT_PORT),
        str(discovered.get("target_scheme") or "http"),
    )
    active_reachable = bool(route_state.get("local_tcp_8123_reachable"))
    discovered_reachable = bool(discovered.get("local_tcp_8123_reachable"))
    pending_identity = (
        str(route_state.get("pending_target_ip") or ""),
        int(route_state.get("pending_target_port") or HA_TARGET_DEFAULT_PORT),
        str(route_state.get("pending_target_scheme") or "http"),
    )

    selected = dict(discovered)
    pending_target = {
        "pending_target_host": None,
        "pending_target_hostname": None,
        "pending_target_ip": None,
        "pending_target_port": None,
        "pending_target_scheme": None,
        "pending_target_source": None,
        "pending_target_type": None,
        "pending_since": None,
    }
    changed = False

    if access_mode == ACCESS_MODE_ROUTE and discovered_identity[0] and discovered_identity != current_identity and active_reachable and discovered_reachable:
        if pending_identity != discovered_identity:
            pending_target = {
                "pending_target_host": discovered.get("target_host"),
                "pending_target_hostname": discovered.get("target_hostname"),
                "pending_target_ip": discovered.get("target_ip"),
                "pending_target_port": discovered.get("target_port"),
                "pending_target_scheme": discovered.get("target_scheme"),
                "pending_target_source": discovered.get("target_source"),
                "pending_target_type": discovered.get("target_type"),
                "pending_since": now,
            }
            selected = {
                **route_state,
                "configured_target": discovered.get("configured_target"),
                "selected_target_ip": discovered.get("selected_target_ip"),
                "target_reachable": active_reachable,
                "local_tcp_8123_reachable": active_reachable,
                "health_status": health_status_for_target(active_reachable, bool(route_state.get("target_ip"))),
                "route_network": route_state.get("route_network"),
                "current_endpoint": route_state.get("current_endpoint"),
                "last_error": None if active_reachable else route_state.get("last_error"),
            }
            LOG.info(
                "ha route target change observed pending_target=%s source=%s debounce_seconds=%s",
                discovered.get("current_endpoint"),
                discovered.get("target_source"),
                TARGET_CHANGE_DEBOUNCE_SECONDS,
            )
        else:
            try:
                pending_since = datetime.fromisoformat(str(route_state.get("pending_since")))
            except Exception:
                pending_since = None
            if pending_since and (datetime.now(timezone.utc) - pending_since).total_seconds() < TARGET_CHANGE_DEBOUNCE_SECONDS:
                pending_target = {
                    "pending_target_host": route_state.get("pending_target_host"),
                    "pending_target_hostname": route_state.get("pending_target_hostname"),
                    "pending_target_ip": route_state.get("pending_target_ip"),
                    "pending_target_port": route_state.get("pending_target_port"),
                    "pending_target_scheme": route_state.get("pending_target_scheme"),
                    "pending_target_source": route_state.get("pending_target_source"),
                    "pending_target_type": route_state.get("pending_target_type"),
                    "pending_since": route_state.get("pending_since"),
                }
                selected = {
                    **route_state,
                    "configured_target": discovered.get("configured_target"),
                    "selected_target_ip": discovered.get("selected_target_ip"),
                    "target_reachable": active_reachable,
                    "local_tcp_8123_reachable": active_reachable,
                    "health_status": health_status_for_target(active_reachable, bool(route_state.get("target_ip"))),
                    "route_network": route_state.get("route_network"),
                    "current_endpoint": route_state.get("current_endpoint"),
                    "last_error": None if active_reachable else route_state.get("last_error"),
                }
            else:
                changed = True
                LOG.info(
                    "ha route target promoted pending_target=%s source=%s",
                    discovered.get("current_endpoint"),
                    discovered.get("target_source"),
                )
    else:
        if discovered_identity != current_identity:
            changed = discovered_identity[0] != "" or current_identity[0] != ""
        if pending_identity[0]:
            LOG.info("ha route pending target cleared current_target=%s", discovered.get("current_endpoint"))

    if access_mode == ACCESS_MODE_PROXY:
        selected = {
            **route_state,
            "configured_target": discovered.get("configured_target"),
            "target_host": discovered.get("target_host"),
            "target_hostname": discovered.get("target_hostname"),
            "selected_target_ip": discovered.get("selected_target_ip"),
            "target_ip": discovered.get("target_ip"),
            "resolved_target_ip": discovered.get("resolved_target_ip") or discovered.get("target_ip"),
            "target_port": discovered.get("target_port") or HA_TARGET_DEFAULT_PORT,
            "target_scheme": discovered.get("target_scheme") or "http",
            "target_type": discovered.get("target_type"),
            "target_source": discovered.get("target_source"),
            "target_reachable": bool(discovered.get("target_reachable")),
            "local_tcp_8123_reachable": bool(discovered.get("local_tcp_8123_reachable")),
            "health_status": "legacy-proxy" if legacy_proxy_url else health_status_for_target(bool(discovered.get("local_tcp_8123_reachable")), bool(discovered.get("target_ip"))),
            "route_network": None,
            "effective_target_cidr": discovered.get("effective_target_cidr"),
            "current_endpoint": legacy_proxy_url,
            "last_error": discovered.get("last_error"),
        }

    desired_routes = selected.get("route_network") if access_mode == ACCESS_MODE_ROUTE else None

    healthy = (
        bool(selected.get("local_tcp_8123_reachable"))
        if access_mode == ACCESS_MODE_ROUTE
        else bool(status.get("connected")) if status else bool(route_state.get("healthy"))
    )
    health_status = (
        str(selected.get("health_status") or "")
        if access_mode == ACCESS_MODE_ROUTE
        else ("legacy-proxy" if legacy_proxy_url else "proxy-offline")
    )
    if health_status != str(route_state.get("health_status") or ""):
        changed = True
        LOG.info(
            "ha route health status changed access_mode=%s from=%s to=%s target=%s",
            access_mode,
            route_state.get("health_status"),
            health_status,
            selected.get("current_endpoint"),
        )

    next_route = {
        **route_state,
        **pending_target,
        "access_mode": access_mode,
        "ha_access_mode": route_state.get("ha_access_mode") or "direct_ip",
        "route_mode": ROUTE_MODE_HOST_ONLY,
        "configured_target": selected.get("configured_target"),
        "target_host": selected.get("target_host"),
        "target_hostname": selected.get("target_hostname"),
        "resolved_target_hostname": selected.get("resolved_target_hostname") or selected.get("target_hostname"),
        "selected_target_ip": selected.get("selected_target_ip"),
        "target_ip": selected.get("target_ip"),
        "resolved_target_ip": selected.get("resolved_target_ip") or selected.get("target_ip"),
        "effective_target_hostname": selected.get("target_hostname"),
        "target_port": selected.get("target_port") or HA_TARGET_DEFAULT_PORT,
        "target_scheme": selected.get("target_scheme") or "http",
        "target_type": selected.get("target_type"),
        "target_source": selected.get("target_source"),
        "local_tcp_8123_reachable": bool(selected.get("local_tcp_8123_reachable")),
        "health_status": health_status,
        "target_reachable": bool(selected.get("target_reachable")),
        "route_network": desired_routes if access_mode == ACCESS_MODE_ROUTE else None,
        "desired_advertise_routes": desired_routes,
        "effective_target_cidr": selected.get("effective_target_cidr")
        or (
            route_network_for_ip(str(selected.get("resolved_target_ip") or selected.get("target_ip") or ""))
            if selected.get("target_ip")
            else None
        ),
        "legacy_proxy_url": legacy_proxy_url,
        "current_endpoint": selected.get("current_endpoint"),
        "healthy": healthy,
        "last_error": selected.get("last_error"),
        "last_resolved_at": now,
        "needs_report": bool(route_state.get("needs_report")) or changed,
    }
    network = route_network_context(state, next_route, latest_options, local_context=local_context)
    next_route.update(network)
    next_route["overlay_identity"] = network.get("overlay_identity")
    if next_route.get("healthy"):
        next_route["last_healthy_at"] = now
    if changed:
        next_route["last_change_at"] = now
        LOG.info(
            "ha route state updated access_mode=%s source=%s endpoint=%s route=%s local_tcp_8123=%s health=%s",
            next_route.get("access_mode"),
            next_route.get("target_source"),
            next_route.get("current_endpoint"),
            next_route.get("route_network"),
            next_route.get("local_tcp_8123_reachable"),
            next_route.get("health_status"),
        )
    if route_state_material_view(route_state) == route_state_material_view(next_route):
        next_route["last_resolved_at"] = route_state.get("last_resolved_at")
        if route_state.get("last_healthy_at") is not None:
            next_route["last_healthy_at"] = route_state.get("last_healthy_at")
        if route_state.get("last_change_at") is not None:
            next_route["last_change_at"] = route_state.get("last_change_at")
        LOG.debug(
            "ha route refresh skipped unchanged endpoint=%s health=%s",
            next_route.get("current_endpoint"),
            next_route.get("health_status"),
        )
    else:
        state["route"] = next_route
        write_json_file(STATE_PATH, state)
        with _state_lock:
            _state.clear()
            _state.update(state)
    with _route_refresh_lock:
        _route_refresh_cache["key"] = cache_key
        _route_refresh_cache["value"] = clone_json(next_route)
        _route_refresh_cache["at"] = now_monotonic
    return next_route


def binding_presentation(binding: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "status": binding.get("status"),
        "valid": bool(binding.get("valid")),
        "deviceId": binding.get("device_id"),
        "homeId": binding.get("home_id"),
        "bindingId": binding.get("binding_id"),
        "deviceBindingId": binding.get("device_binding_id"),
        "signedBindingToken": binding.get("signed_binding_token"),
        "expectedNetbirdLabel": binding.get("expected_netbird_label"),
        "netbirdLabels": binding.get("netbird_labels") or [],
        "setupKeyId": binding.get("setup_key_id"),
        "setupKeyCreatedAt": binding.get("setup_key_created_at"),
        "setupKeyLineage": binding.get("setup_key_lineage"),
        "missingFields": binding.get("missing_fields") or [],
        "netbirdLabelApplyStatus": binding.get("netbird_label_apply_status"),
    }


def current_target_resolution_state(route_state: Dict[str, Any]) -> str:
    if route_state.get("pending_target_ip") or route_state.get("pending_target_hostname"):
        return "pending_target_change"
    if route_state.get("target_ip") and route_state.get("target_hostname"):
        return "hostname_resolved"
    if route_state.get("target_ip"):
        return "resolved_ip"
    if route_state.get("target_hostname") or route_state.get("target_host"):
        return "configured_unresolved"
    return "unresolved"


def heartbeat_telemetry_gaps(route_state: Dict[str, Any]) -> list[str]:
    gaps: list[str] = []
    resolution_state = current_target_resolution_state(route_state)
    if resolution_state in {"unresolved", "configured_unresolved", "pending_target_change"}:
        gaps.append(f"target_observation:{resolution_state}")
    if route_state.get("access_mode") == ACCESS_MODE_ROUTE:
        if not route_state.get("route_ids"):
            gaps.append("route_ids_missing")
        if not route_state.get("peer_group_ids"):
            gaps.append("peer_group_ids_missing")
        if not route_state.get("policy_ids"):
            gaps.append("policy_ids_missing")
    return gaps


def build_health_report(
    status: Dict[str, Any],
    state: Dict[str, Any],
    options: Optional[Dict[str, Any]] = None,
    *,
    reported_at: Optional[str] = None,
) -> Dict[str, Any]:
    route_state = dict(state.get("route") or {})
    binding = normalize_binding_state(state)
    latest_options = options or load_options()
    effective_reported_at = reported_at or now_iso()
    transport_access_mode = effective_access_mode(latest_options, state)
    ha_access_mode = effective_home_assistant_access_mode(route_state)
    agent_running = bool(state.get("agent_running"))
    netbird_connected = bool(status.get("connected"))
    route_healthy = bool(route_state.get("healthy"))
    local_tcp_reachable = bool(route_state.get("local_tcp_8123_reachable"))
    target_resolution_state = current_target_resolution_state(route_state)
    network = route_network_context(state, route_state, latest_options)
    current_error = (
        normalize_optional_string(state.get("heartbeat_error"))
        or normalize_optional_string(route_state.get("last_error"))
        or normalize_optional_string(state.get("last_error"))
    )
    health_result = "; ".join(
        [
            f"access_mode={transport_access_mode}",
            f"ha_access_mode={ha_access_mode}",
            f"agent_running={'yes' if agent_running else 'no'}",
            f"netbird_connected={'yes' if netbird_connected else 'no'}",
            f"route_healthy={'yes' if route_healthy else 'no'}",
            f"local_tcp_8123_reachable={'yes' if local_tcp_reachable else 'no'}",
            f"target_resolution_state={target_resolution_state}",
            f"network_status={network.get('network_status') or 'waiting'}",
            f"same_lan_detected={'yes' if network.get('same_lan_detected') else 'no'}",
            f"exact_ip_conflict={'yes' if network.get('exact_ip_conflict') else 'no'}",
            f"subnet_overlap={'yes' if network.get('subnet_overlap') else 'no'}",
            f"local_bypass_recommended={'yes' if network.get('local_bypass_recommended') else 'no'}",
            f"health_status={route_state.get('health_status') or 'unknown'}",
            f"binding_status={binding.get('status') or 'missing'}",
            *(["heartbeat_error=" + current_error] if current_error else []),
        ]
    )
    return {
        "reported_at": effective_reported_at,
        "interval_seconds": int(HEALTH_REPORT_INTERVAL_SECONDS),
        "access_mode": transport_access_mode,
        "ha_access_mode": ha_access_mode,
        "agent_running": agent_running,
        "netbird_connected": netbird_connected,
        "route_healthy": route_healthy,
        "local_tcp_8123_reachable": local_tcp_reachable,
        "target_resolution_state": target_resolution_state,
        "network_status": network.get("network_status"),
        "same_lan_detected": network.get("same_lan_detected"),
        "exact_ip_conflict": network.get("exact_ip_conflict"),
        "subnet_overlap": network.get("subnet_overlap"),
        "local_bypass_recommended": network.get("local_bypass_recommended"),
        "local_bypass_reason": network.get("local_bypass_reason"),
        "local_ipv4_addresses": network.get("local_ipv4_addresses") or [],
        "local_ipv4_subnets": network.get("local_ipv4_subnets") or [],
        "local_ipv4_interfaces": network.get("local_ipv4_interfaces") or [],
        "local_ipv4_source": network.get("local_ipv4_source"),
        "local_ipv4_error": network.get("local_ipv4_error"),
        "matching_local_subnets": network.get("matching_local_subnets") or [],
        "effective_target_cidr": network.get("effective_target_cidr"),
        "effective_target_hostname": network.get("effective_target_hostname"),
        "effective_target_identity": network.get("effective_target_identity"),
        "overlay_identity": network.get("overlay_identity"),
        "hometunnel_dns_hostname": network.get("hometunnel_dns_hostname"),
        "hometunnel_display_identity": network.get("hometunnel_display_identity"),
        "overlay_identity_basis": network.get("overlay_identity_basis"),
        "current_heartbeat_error": normalize_optional_string(state.get("heartbeat_error")),
        "current_health_error": current_error,
        "last_health_check_at": effective_reported_at,
        "last_agent_report_at": effective_reported_at,
        "last_health_result": health_result,
    }


def build_ha_info(
    state: Optional[Dict[str, Any]] = None,
    options: Optional[Dict[str, Any]] = None,
    *,
    status: Optional[Dict[str, Any]] = None,
    binding: Optional[Dict[str, Any]] = None,
    health_report: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    state_snapshot = state or read_state_snapshot()
    latest_options = options or load_options()
    route_state = dict(state_snapshot.get("route") or {})
    current_status = status or dict(state_snapshot.get("netbird") or {})
    current_binding = binding or normalize_binding_state(state_snapshot)
    current_health = health_report or build_health_report(current_status, state_snapshot, latest_options)
    target_endpoint = route_state.get("current_endpoint")
    target_host = route_state.get("target_host")
    target_hostname = route_state.get("target_hostname")
    resolved_target_hostname = route_state.get("resolved_target_hostname") or target_hostname
    network = route_network_context(state_snapshot, route_state, latest_options)
    transport_mode = effective_access_mode(latest_options, state_snapshot)
    ha_access_mode = effective_home_assistant_access_mode(route_state)
    target_ip = route_state.get("target_ip")
    target_port = route_state.get("target_port")
    route_mode = route_state.get("route_mode")
    target_reachable = route_state.get("target_reachable")
    health_status = route_state.get("health_status")
    route_healthy = route_state.get("healthy")
    local_reachability = route_state.get("local_tcp_8123_reachable")
    routing_peer_capable = bool(current_status.get("connected")) and bool(target_ip)
    effective_target_hostname = network.get("effective_target_hostname")
    if effective_target_hostname is None and ha_access_mode != "hometunnel_address":
        effective_target_hostname = target_hostname
    hometunnel_dns_hostname = network.get("hometunnel_dns_hostname")
    hometunnel_display_identity = network.get("hometunnel_display_identity")
    return {
        "hostname": socket.gethostname(),
        "platform": "haos-addon",
        "transport_mode": transport_mode,
        "transportMode": transport_mode,
        "access_mode": ha_access_mode,
        "accessMode": ha_access_mode,
        "target_ip": target_ip,
        "targetIp": target_ip,
        "target_hostname": effective_target_hostname,
        "targetHostname": effective_target_hostname,
        "resolved_target_hostname": resolved_target_hostname,
        "resolvedTargetHostname": resolved_target_hostname,
        "effective_target_hostname": effective_target_hostname,
        "effectiveTargetHostname": effective_target_hostname,
        "target_port": target_port,
        "targetPort": target_port,
        "target_endpoint": target_endpoint,
        "targetEndpoint": target_endpoint,
        "route_mode": route_mode,
        "routeMode": route_mode,
        "selected_target_ip": route_state.get("selected_target_ip"),
        "selectedTargetIp": route_state.get("selected_target_ip"),
        "resolved_target_ip": route_state.get("resolved_target_ip") or target_ip,
        "resolvedTargetIp": route_state.get("resolved_target_ip") or target_ip,
        "target_reachable": target_reachable,
        "targetReachable": target_reachable,
        "local_reachability": local_reachability,
        "localReachability": local_reachability,
        "local_tcp_8123_reachable": local_reachability,
        "localTcp8123Reachable": local_reachability,
        "route_healthy": route_healthy,
        "routeHealthy": route_healthy,
        "health_status": health_status,
        "healthStatus": health_status,
        "health_message": current_health.get("last_health_result"),
        "healthMessage": current_health.get("last_health_result"),
        "agent_running": current_health.get("agent_running"),
        "agentRunning": current_health.get("agent_running"),
        "netbird_connected": current_health.get("netbird_connected"),
        "netbirdConnected": current_health.get("netbird_connected"),
        "target_resolution_state": current_health.get("target_resolution_state"),
        "targetResolutionState": current_health.get("target_resolution_state"),
        "heartbeat_error": current_health.get("current_heartbeat_error"),
        "heartbeatError": current_health.get("current_heartbeat_error"),
        "health_error": current_health.get("current_health_error"),
        "healthError": current_health.get("current_health_error"),
        "last_health_check_at": current_health.get("last_health_check_at"),
        "lastHealthCheckAt": current_health.get("last_health_check_at"),
        "last_agent_report_at": current_health.get("last_agent_report_at"),
        "lastAgentReportAt": current_health.get("last_agent_report_at"),
        "last_health_result": current_health.get("last_health_result"),
        "lastHealthResult": current_health.get("last_health_result"),
        "network_status": network.get("network_status"),
        "networkStatus": network.get("network_status"),
        "same_lan_detected": network.get("same_lan_detected"),
        "sameLanDetected": network.get("same_lan_detected"),
        "exact_ip_conflict": network.get("exact_ip_conflict"),
        "exactIpConflict": network.get("exact_ip_conflict"),
        "subnet_overlap": network.get("subnet_overlap"),
        "subnetOverlap": network.get("subnet_overlap"),
        "local_bypass_recommended": network.get("local_bypass_recommended"),
        "localBypassRecommended": network.get("local_bypass_recommended"),
        "local_bypass_reason": network.get("local_bypass_reason"),
        "localBypassReason": network.get("local_bypass_reason"),
        "local_ipv4_addresses": network.get("local_ipv4_addresses") or [],
        "localIPv4Addresses": network.get("local_ipv4_addresses") or [],
        "local_ipv4_subnets": network.get("local_ipv4_subnets") or [],
        "localIPv4Subnets": network.get("local_ipv4_subnets") or [],
        "local_ipv4_interfaces": network.get("local_ipv4_interfaces") or [],
        "localIPv4Interfaces": network.get("local_ipv4_interfaces") or [],
        "local_ipv4_source": network.get("local_ipv4_source"),
        "localIPv4Source": network.get("local_ipv4_source"),
        "local_ipv4_error": network.get("local_ipv4_error"),
        "localIPv4Error": network.get("local_ipv4_error"),
        "matching_local_subnets": network.get("matching_local_subnets") or [],
        "matchingLocalSubnets": network.get("matching_local_subnets") or [],
        "effective_target_cidr": network.get("effective_target_cidr"),
        "effectiveTargetCidr": network.get("effective_target_cidr"),
        "effective_target_identity": network.get("effective_target_identity"),
        "effectiveTargetIdentity": network.get("effective_target_identity"),
        "overlay_identity": hometunnel_dns_hostname,
        "overlayIdentity": hometunnel_dns_hostname,
        "overlay_identity_display": hometunnel_display_identity,
        "overlayIdentityDisplay": hometunnel_display_identity,
        "hometunnel_dns_hostname": hometunnel_dns_hostname,
        "hometunnelDnsHostname": hometunnel_dns_hostname,
        "hometunnel_display_identity": hometunnel_display_identity,
        "hometunnelDisplayIdentity": hometunnel_display_identity,
        "overlay_identity_basis": network.get("overlay_identity_basis"),
        "overlayIdentityBasis": network.get("overlay_identity_basis"),
        "routing_peer_capable": routing_peer_capable,
        "routingPeerCapable": routing_peer_capable,
        "binding_status": current_binding.get("status"),
        "bindingStatus": current_binding.get("status"),
        "expected_netbird_label": current_binding.get("expected_netbird_label"),
        "expectedNetbirdLabel": current_binding.get("expected_netbird_label"),
        "target": {
            "endpoint": target_endpoint,
            "host": target_host,
            "hostname": effective_target_hostname,
            "resolved_hostname": resolved_target_hostname,
            "selected_target_ip": route_state.get("selected_target_ip"),
            "ip": target_ip,
            "resolved_target_ip": route_state.get("resolved_target_ip") or target_ip,
            "port": target_port,
            "route_network": route_state.get("route_network"),
            "effective_target_cidr": network.get("effective_target_cidr"),
            "target_source": route_state.get("target_source"),
            "reachable": target_reachable,
            "local_tcp_8123_reachable": local_reachability,
            "health_status": health_status,
            "legacy_proxy_url": route_state.get("legacy_proxy_url"),
        },
        "network": network,
        "binding": {
            "status": current_binding.get("status"),
            "expected_netbird_label": current_binding.get("expected_netbird_label"),
            "missing_fields": current_binding.get("missing_fields") or [],
            "netbird_label_apply_status": current_binding.get("netbird_label_apply_status"),
        },
    }


def pid_is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def read_agent_pid() -> Optional[int]:
    try:
        raw = NETBIRD_AGENT_PID_PATH.read_text(encoding="utf-8").strip()
        if not raw:
            return None
        return int(raw)
    except Exception:
        return None


def write_agent_pid(pid: int) -> None:
    NETBIRD_AGENT_PID_PATH.write_text(str(pid), encoding="utf-8")
    chmod_if_exists(NETBIRD_AGENT_PID_PATH, 0o600)


def clear_agent_pid() -> None:
    try:
        NETBIRD_AGENT_PID_PATH.unlink()
    except FileNotFoundError:
        pass


def read_daemon_pid() -> Optional[int]:
    try:
        raw = NETBIRD_DAEMON_PID_PATH.read_text(encoding="utf-8").strip()
        if not raw:
            return None
        return int(raw)
    except Exception:
        return None


def write_daemon_pid(pid: int) -> None:
    NETBIRD_DAEMON_PID_PATH.write_text(str(pid), encoding="utf-8")
    chmod_if_exists(NETBIRD_DAEMON_PID_PATH, 0o600)


def clear_daemon_pid() -> None:
    try:
        NETBIRD_DAEMON_PID_PATH.unlink()
    except FileNotFoundError:
        pass


def has_netbird_credentials(state: Dict[str, Any]) -> bool:
    return bool(
        state.get("paired")
        and state.get("device_id")
        and state.get("home_id")
        and state.get("management_url")
        and state.get("device_token")
    )


def missing_enrollment_reason(state: Dict[str, Any]) -> Optional[str]:
    required_fields = ("paired", "device_id", "home_id", "management_url", "device_token")
    for field in required_fields:
        value = state.get(field)
        if field == "paired":
            if not value:
                return "missing enrollment state"
            continue
        if value in (None, "", []):
            return "missing enrollment state"
    return None


def is_netbird_agent_running() -> bool:
    agent_pid = read_agent_pid()
    if not agent_pid:
        return False
    if pid_is_running(agent_pid):
        return True
    clear_agent_pid()
    return False


def is_netbird_daemon_running() -> bool:
    daemon_pid = read_daemon_pid()
    if not daemon_pid:
        return False
    if pid_is_running(daemon_pid):
        return True
    clear_daemon_pid()
    return False


def netbird_base_args() -> list[str]:
    return [
        "--config",
        str(NETBIRD_CONFIG_PATH),
        "--daemon-addr",
        f"unix://{NETBIRD_SOCKET_PATH}",
    ]


def netbird_command(*args: str) -> list[str]:
    return ["netbird", *netbird_base_args(), *args]


def parse_labels(value: Any) -> list[str]:
    if isinstance(value, list):
        return unique_strings(value)
    if isinstance(value, str):
        stripped = value.strip()
        return [stripped] if stripped else []
    return []


def binding_source_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def merge_binding_sources(
    existing_binding: Any,
    incoming_binding: Any,
    *,
    clear_portal_validation: bool = False,
    clear_keys: Optional[set[str]] = None,
) -> Dict[str, Any]:
    existing = binding_source_dict(existing_binding)
    incoming = binding_source_dict(incoming_binding)
    merged = dict(existing)
    keys_to_clear = clear_keys or set()

    for key in keys_to_clear:
        merged[key] = None
        if key == "netbird_labels":
            merged[key] = []

    for key in (
        "device_id",
        "home_id",
        "binding_id",
        "device_binding_id",
        "signed_binding_token",
        "expected_netbird_label",
        "setup_key_id",
        "setup_key_created_at",
        "received_at",
        "persisted_at",
        "presented_at",
    ):
        value = normalize_optional_string(incoming.get(key))
        if value:
            merged[key] = value

    lineage = normalize_optional_json_value(incoming.get("setup_key_lineage"))
    if has_meaningful_value(lineage):
        merged["setup_key_lineage"] = lineage

    merged["netbird_labels"] = unique_strings(
        [
            *parse_labels(existing.get("netbird_labels")),
            *parse_labels(existing.get("labels")),
            *parse_labels(incoming.get("netbird_labels")),
            *parse_labels(incoming.get("labels")),
        ]
    )

    if clear_portal_validation:
        merged["portal_validation_error"] = None
        merged["portal_validation_reported_at"] = None
    else:
        portal_validation_error = normalize_optional_string(incoming.get("portal_validation_error"))
        portal_validation_reported_at = normalize_optional_string(incoming.get("portal_validation_reported_at"))
        if portal_validation_error:
            merged["portal_validation_error"] = portal_validation_error
        if portal_validation_reported_at:
            merged["portal_validation_reported_at"] = portal_validation_reported_at

    return merged


def normalize_binding_state(state: Dict[str, Any]) -> Dict[str, Any]:
    binding = default_binding_state()
    stored_binding = binding_source_dict(state.get("binding"))
    binding.update(stored_binding)

    provided_device_id = normalize_optional_string(binding.get("device_id"))
    provided_home_id = normalize_optional_string(binding.get("home_id"))
    state_device_id = normalize_optional_string(state.get("device_id"))
    state_home_id = normalize_optional_string(state.get("home_id"))
    effective_device_id = state_device_id or provided_device_id
    effective_home_id = state_home_id or provided_home_id

    labels = unique_strings(
        [
            *parse_labels(state.get("labels")),
            *parse_labels(binding.get("netbird_labels")),
            *parse_labels(binding.get("labels")),
        ]
    )
    expected_label = normalize_optional_string(binding.get("expected_netbird_label"))
    if not expected_label:
        expected_label = next((label for label in labels if label.startswith("ht-device-")), None)
    if not expected_label:
        expected_label = binding_device_label(effective_device_id)
    if expected_label and expected_label not in labels:
        labels.append(expected_label)

    device_binding_id = normalize_optional_string(binding.get("device_binding_id"))
    binding_id = normalize_optional_string(binding.get("binding_id")) or device_binding_id
    signed_binding_token = normalize_optional_string(binding.get("signed_binding_token"))
    setup_key_id = normalize_optional_string(binding.get("setup_key_id"))
    setup_key_created_at = normalize_optional_string(binding.get("setup_key_created_at"))
    setup_key_lineage = normalize_optional_json_value(binding.get("setup_key_lineage"))
    portal_validation_error = normalize_optional_string(binding.get("portal_validation_error"))
    portal_validation_reported_at = normalize_optional_string(binding.get("portal_validation_reported_at"))

    validation_error = None
    if provided_device_id and state_device_id and provided_device_id != state_device_id:
        validation_error = "binding_device_id_mismatch"
    elif provided_home_id and state_home_id and provided_home_id != state_home_id:
        validation_error = "binding_home_id_mismatch"
    elif not effective_device_id or not effective_home_id:
        validation_error = "binding_identity_missing"
    elif not expected_label:
        validation_error = "expected_netbird_label_missing"
    elif portal_validation_error:
        validation_error = portal_validation_error

    missing_fields: list[str] = []
    if not effective_device_id:
        missing_fields.append("device_id")
    if not effective_home_id:
        missing_fields.append("home_id")
    if not expected_label:
        missing_fields.append("expected_netbird_label")
    if not (binding_id or device_binding_id):
        missing_fields.append("binding_id")

    any_binding_metadata = bool(
        effective_device_id
        or effective_home_id
        or labels
        or binding_id
        or device_binding_id
        or signed_binding_token
        or setup_key_id
        or setup_key_created_at
        or setup_key_lineage
    )

    if validation_error:
        status = "invalid"
        valid = False
    elif not any_binding_metadata:
        status = "missing"
        valid = False
    elif missing_fields:
        status = "partial"
        valid = bool(effective_device_id and effective_home_id and expected_label)
    else:
        status = "bound"
        valid = True

    return {
        **binding,
        "device_id": effective_device_id,
        "home_id": effective_home_id,
        "binding_id": binding_id,
        "device_binding_id": device_binding_id,
        "signed_binding_token": signed_binding_token,
        "expected_netbird_label": expected_label,
        "netbird_labels": labels,
        "setup_key_id": setup_key_id,
        "setup_key_created_at": setup_key_created_at,
        "setup_key_lineage": setup_key_lineage,
        "status": status,
        "valid": valid,
        "validation_error": validation_error if validation_error else ("binding_missing" if status == "missing" else None),
        "portal_validation_error": portal_validation_error,
        "portal_validation_reported_at": portal_validation_reported_at,
        "missing_fields": missing_fields,
        "netbird_label_apply_status": normalize_optional_string(binding.get("netbird_label_apply_status")) or "pending",
    }


PORTAL_HARD_BINDING_INVALIDATION_CODES = {
    *BINDING_FAILURE_CODES,
}


def transport_ready_from_state(state: Dict[str, Any]) -> bool:
    netbird = dict(state.get("netbird") or {})
    return bool(netbird.get("connected")) and bool(normalize_optional_string(netbird.get("peer_id")))


def binding_ready_from_state(state: Dict[str, Any]) -> bool:
    binding = normalize_binding_state(state)
    return bool(binding.get("valid")) and bool(normalize_optional_string(state.get("device_id"))) and bool(
        normalize_optional_string(state.get("home_id"))
    )


def status_view_from_state(state: Dict[str, Any], options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    latest_options = options or load_options()
    current = clone_json(state)
    current["paired"] = bool(
        current.get("device_id")
        and current.get("home_id")
        and current.get("management_url")
        and current.get("device_token")
    )
    current["binding"] = normalize_binding_state(current)
    apply_pairing_session_to_state(current, normalize_pairing_session_state(current))
    current["route"] = {
        **dict(current.get("route") or {}),
        "access_mode": effective_access_mode(latest_options, current),
    }
    current["transport_ready"] = transport_ready_from_state(current)
    current["binding_ready"] = binding_ready_from_state(current)
    local_status, local_status_detail = derive_local_status(current)
    current["local_status"] = local_status
    current["local_status_detail"] = local_status_detail
    if should_clear_pairing_session_for_state(current):
        clear_pairing_session_state(current)
    current["pairing_state"] = derive_pairing_state(current)
    pairing_session = normalize_pairing_session_state(current)
    start_allowed, blocked_reason = pairing_start_gate(current, pairing_session)
    pairing_session["active"] = pairing_session_is_reusable(pairing_session)
    pairing_session["remaining_seconds"] = pairing_session_remaining_seconds(pairing_session)
    pairing_session["start_allowed"] = start_allowed
    pairing_session["start_blocked_reason"] = blocked_reason
    current["pairing_session"] = pairing_session
    current["pairing_start_allowed"] = start_allowed
    current["pairing_start_blocked_reason"] = blocked_reason
    return current


def effective_binding_labels(state: Dict[str, Any]) -> list[str]:
    binding = normalize_binding_state(state)
    labels = unique_strings([*parse_labels(state.get("labels")), *parse_labels(binding.get("netbird_labels"))])
    expected_label = normalize_optional_string(binding.get("expected_netbird_label"))
    if expected_label and expected_label not in labels:
        labels.append(expected_label)
    return labels


def binding_rotation_fields(previous: Dict[str, Any], current: Dict[str, Any]) -> list[str]:
    changed: list[str] = []
    for key in (
        "device_id",
        "home_id",
        "binding_id",
        "device_binding_id",
        "signed_binding_token",
        "expected_netbird_label",
        "netbird_labels",
        "setup_key_id",
        "setup_key_created_at",
        "setup_key_lineage",
    ):
        if normalize_optional_json_value(previous.get(key)) != normalize_optional_json_value(current.get(key)):
            changed.append(key)
    return changed


def extract_binding_metadata(
    enroll_result: Dict[str, Any],
    *,
    onboarding: Dict[str, Any],
    netbird_info: Dict[str, Any],
    device_id: Any,
    home_id: Any,
    labels: list[str],
) -> Dict[str, Any]:
    binding_info: Dict[str, Any] = {}
    for candidate in (
        enroll_result.get("binding"),
        enroll_result.get("device_binding"),
        onboarding.get("binding"),
        onboarding.get("device_binding"),
        netbird_info.get("binding"),
        netbird_info.get("device_binding"),
    ):
        if isinstance(candidate, dict):
            binding_info.update(candidate)

    expected_label = (
        normalize_optional_string(first_present(binding_info, "expected_netbird_label", "expectedNetbirdLabel"))
        or next((label for label in labels if label.startswith("ht-device-")), None)
        or binding_device_label(normalize_optional_string(device_id))
    )

    return {
        "device_id": normalize_optional_string(first_present(binding_info, "device_id", "deviceId") or device_id),
        "home_id": normalize_optional_string(first_present(binding_info, "home_id", "homeId") or home_id),
        "binding_id": normalize_optional_string(
            first_present(binding_info, "binding_id", "bindingId")
            or first_present(binding_info, "device_binding_id", "deviceBindingId")
        ),
        "device_binding_id": normalize_optional_string(first_present(binding_info, "device_binding_id", "deviceBindingId")),
        "signed_binding_token": normalize_optional_string(
            first_present(
                binding_info,
                "signed_binding_token",
                "signedBindingToken",
                "binding_token",
                "bindingToken",
            )
        ),
        "expected_netbird_label": expected_label,
        "netbird_labels": labels,
        "setup_key_id": normalize_optional_string(
            first_present(binding_info, "setup_key_id", "setupKeyId")
            or first_present(netbird_info, "setup_key_id", "setupKeyId")
            or first_present(enroll_result, "setup_key_id", "setupKeyId")
            or first_present(onboarding, "setup_key_id", "setupKeyId")
        ),
        "setup_key_created_at": normalize_optional_string(
            first_present(binding_info, "setup_key_created_at", "setupKeyCreatedAt")
            or first_present(netbird_info, "setup_key_created_at", "setupKeyCreatedAt")
            or first_present(enroll_result, "setup_key_created_at", "setupKeyCreatedAt")
            or first_present(onboarding, "setup_key_created_at", "setupKeyCreatedAt")
        ),
        "setup_key_lineage": normalize_optional_json_value(
            first_present(binding_info, "setup_key_lineage", "setupKeyLineage")
            or first_present(netbird_info, "setup_key_lineage", "setupKeyLineage")
            or first_present(enroll_result, "setup_key_lineage", "setupKeyLineage")
            or first_present(onboarding, "setup_key_lineage", "setupKeyLineage")
        ),
    }


def extract_enrollment_fields(enroll_result: Dict[str, Any]) -> Dict[str, Any]:
    onboarding = binding_source_dict(enroll_result.get("onboarding"))
    netbird_info = binding_source_dict(enroll_result.get("netbird")) or binding_source_dict(onboarding.get("netbird"))
    device_id = first_present(enroll_result, "device_id", "deviceId") or first_present(onboarding, "device_id", "deviceId")
    home_id = first_present(enroll_result, "home_id", "homeId") or first_present(onboarding, "home_id", "homeId")
    raw_labels = (
        first_present(enroll_result, "labels")
        or first_present(onboarding, "labels")
        or first_present(netbird_info, "labels", "peer_name_or_labels", "peerNameOrLabels")
    )
    labels = parse_labels(raw_labels)
    return {
        "device_id": device_id,
        "home_id": home_id,
        "netbird_peer_id": extract_portal_netbird_peer_id(enroll_result) or extract_portal_netbird_peer_id(onboarding),
        "device_token": first_present(enroll_result, "device_token", "deviceToken") or first_present(onboarding, "device_token", "deviceToken"),
        "labels": labels,
        "management_url": first_present(netbird_info, "management_url", "managementUrl"),
        "peer_name": first_present(netbird_info, "peer_name", "peerName"),
        "setup_key": first_present(netbird_info, "setup_key", "setupKey"),
        "binding": extract_binding_metadata(
            enroll_result,
            onboarding=onboarding,
            netbird_info=netbird_info,
            device_id=device_id,
            home_id=home_id,
            labels=labels,
        ),
    }


def merge_enrollment_fields(state: Dict[str, Any], incoming_fields: Dict[str, Any]) -> Dict[str, Any]:
    incoming_binding = binding_source_dict(incoming_fields.get("binding"))
    merged_labels = unique_strings(parse_labels(incoming_fields.get("labels")))
    merged_device_id = normalize_optional_string(incoming_fields.get("device_id"))
    merged_home_id = normalize_optional_string(incoming_fields.get("home_id"))

    return {
        "device_id": merged_device_id,
        "home_id": merged_home_id,
        "device_token": normalize_optional_string(incoming_fields.get("device_token")),
        "netbird_peer_id": normalize_optional_string(incoming_fields.get("netbird_peer_id")),
        "labels": merged_labels,
        "management_url": normalize_optional_string(incoming_fields.get("management_url")),
        "peer_name": normalize_optional_string(incoming_fields.get("peer_name")),
        "setup_key": normalize_optional_string(incoming_fields.get("setup_key")),
        "binding": merge_binding_sources({}, {**incoming_binding, "netbird_labels": merged_labels}, clear_portal_validation=True),
    }


def has_recoverable_enrollment_fields(fields: Dict[str, Any]) -> bool:
    required = ("device_id", "home_id", "management_url", "setup_key", "device_token")
    return all(fields.get(key) not in (None, "", []) for key in required)


def portal_binding_status_details(response: Dict[str, Any]) -> tuple[Optional[str], list[str]]:
    if not isinstance(response, dict):
        return None, []
    payload = binding_source_dict(response.get("device_binding"))
    status = normalize_optional_string(first_present(payload, "status", "binding_status", "bindingStatus"))
    diagnostics_raw = first_present(payload, "diagnostics", "binding_diagnostics", "bindingDiagnostics")
    diagnostics = unique_strings(diagnostics_raw if isinstance(diagnostics_raw, list) else [diagnostics_raw])
    return status, diagnostics


def apply_portal_binding_validation_result(state: Dict[str, Any], response: Dict[str, Any], *, reported_at: str) -> None:
    portal_binding_status, portal_binding_diagnostics = portal_binding_status_details(response)
    if not portal_binding_status:
        return

    if portal_binding_status == "binding_validated":
        state["binding"] = normalize_binding_state(
            {
                **state,
                "binding": merge_binding_sources(
                    state.get("binding"),
                    {
                        "portal_validation_error": None,
                        "portal_validation_reported_at": reported_at,
                    },
                    clear_portal_validation=True,
                ),
            }
        )
        state["last_error"] = None
        state["recovery_state"] = None
        return

    if portal_binding_status not in PORTAL_HARD_BINDING_INVALIDATION_CODES:
        return

    if portal_binding_status == "binding_token_stale":
        recovery_state = "stale_binding"
    elif portal_binding_status == "binding_peer_mismatch":
        recovery_state = "peer_mismatch"
    elif portal_binding_status == "binding_device_not_haos":
        recovery_state = "fatal_misconfiguration"
    else:
        recovery_state = "re_pair_required"
    # Portal validation is authoritative for revoke/rotate/mismatch cases. Keep the
    # existing device/home context for operator visibility, but stop treating the
    # stored binding token/IDs as valid until a fresh enrollment replaces them.
    state["binding"] = normalize_binding_state(
        {
            **state,
            "binding": merge_binding_sources(
                state.get("binding"),
                {
                    "portal_validation_error": portal_binding_status,
                    "portal_validation_reported_at": reported_at,
                },
                clear_keys={"binding_id", "device_binding_id", "signed_binding_token"},
            ),
        }
    )
    clear_setup_key_artifacts(state)
    state["recovery_state"] = recovery_state
    state["last_error"] = portal_binding_status
    if portal_binding_diagnostics:
        LOG.warning(
            "portal binding invalidation status=%s diagnostics=%s",
            portal_binding_status,
            ",".join(portal_binding_diagnostics),
        )


def is_private_management_url(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").strip().lower()
    if not host:
        return True
    if host in {"localhost", "management", "netbird-management"}:
        return True
    if host.endswith(".local") or host.endswith(".internal"):
        return True
    try:
        address = ipaddress.ip_address(host)
        return address.is_private or address.is_loopback or address.is_link_local
    except ValueError:
        return "." not in host


def stop_netbird_daemon() -> None:
    daemon_pid = read_daemon_pid()
    if daemon_pid and pid_is_running(daemon_pid):
        try:
            os.kill(daemon_pid, signal.SIGTERM)
        except OSError:
            pass
        deadline = time.time() + 10
        while time.time() < deadline:
            if not pid_is_running(daemon_pid):
                break
            time.sleep(0.2)
        if pid_is_running(daemon_pid):
            try:
                os.kill(daemon_pid, signal.SIGKILL)
            except OSError:
                pass
    clear_daemon_pid()
    try:
        NETBIRD_SOCKET_PATH.unlink()
    except FileNotFoundError:
        pass


def stop_agent_supervisor() -> None:
    agent_pid = read_agent_pid()
    if agent_pid and pid_is_running(agent_pid):
        try:
            os.kill(agent_pid, signal.SIGTERM)
        except OSError:
            pass
        deadline = time.time() + 10
        while time.time() < deadline:
            if not pid_is_running(agent_pid):
                break
            time.sleep(0.2)
        if pid_is_running(agent_pid):
            try:
                os.kill(agent_pid, signal.SIGKILL)
            except OSError:
                pass
    clear_agent_pid()


def delete_path_if_exists(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except Exception:
        LOG.warning("failed to delete path=%s", path)


def clear_local_identity_state(state: Dict[str, Any], *, reset_route: bool = False) -> Dict[str, bool]:
    before = clone_json(state)
    state["device_auth"] = default_device_auth_state()
    state["pairing_session"] = default_pairing_session_state()
    state["pairing_state"] = "unpaired"
    state["paired"] = False
    state["labels"] = []
    state["home_id"] = None
    state["device_id"] = None
    state["netbird_peer_id"] = None
    state["binding"] = default_binding_state()
    state["peer_name"] = None
    state["management_url"] = None
    state["setup_key"] = None
    state["device_token"] = None
    state["agent_running"] = False
    state["last_pair_check"] = None
    state["last_heartbeat_at"] = None
    state["last_heartbeat_result"] = None
    state["last_heartbeat_destination"] = None
    state["heartbeat_error"] = None
    state["last_health_check_at"] = None
    state["last_agent_report_at"] = None
    state["last_health_result"] = None
    state["last_health_report_error"] = None
    state["recovery_state"] = None
    state["local_status"] = None
    state["local_status_detail"] = None
    state["last_error"] = None
    state["netbird"] = {
        "connected": False,
        "peer_id": None,
        "wireguard_public_key": None,
        "peer_ip": None,
        "peer_name": None,
        "remote_peers": [],
        "raw": None,
    }
    if reset_route:
        state["route"] = {
            **default_state()["route"],
            "access_mode": effective_access_mode(load_options(), state),
        }
    else:
        route_state = dict(state.get("route") or {})
        for key in (
            "hometunnel_dns_hostname",
            "hometunnel_display_identity",
            "overlay_identity",
            "overlay_identity_basis",
            "effective_target_identity",
            "route_ids",
            "peer_group_ids",
            "policy_ids",
            "applied_advertise_routes",
            "routing_peer_id",
        ):
            if key in route_state:
                route_state[key] = [] if key in {"route_ids", "peer_group_ids", "policy_ids"} else None
        state["route"] = route_state
    state["transport_ready"] = False
    state["binding_ready"] = False
    fields = {
        "home_id": bool(before.get("home_id")),
        "device_id": bool(before.get("device_id")),
        "binding_id": bool(safe_binding_identifier(normalize_binding_state(before))),
        "device_token": bool(before.get("device_token")),
        "setup_key": bool(before.get("setup_key")),
        "pairing_session": any(bool(v) for v in dict(before.get("pairing_session") or {}).values()),
        "recovery_state": bool(before.get("recovery_state")),
        "heartbeat_error": bool(before.get("heartbeat_error")),
        "netbird_peer_id": bool(before.get("netbird_peer_id")),
    }
    LOG.info(
        "local identity cleared home_id=%s device_id=%s binding_id=%s device_token=%s setup_key=%s pairing_session=%s recovery_state=%s heartbeat_error=%s netbird_peer_id=%s",
        fields["home_id"],
        fields["device_id"],
        fields["binding_id"],
        fields["device_token"],
        fields["setup_key"],
        fields["pairing_session"],
        fields["recovery_state"],
        fields["heartbeat_error"],
        fields["netbird_peer_id"],
    )
    return fields


def portal_reset_cleanup_result(state: Dict[str, Any]) -> Dict[str, Any]:
    device_token = normalize_optional_string(state.get("device_token"))
    device_id = normalize_optional_string(state.get("device_id"))
    home_id = normalize_optional_string(state.get("home_id"))
    binding = normalize_binding_state(state)
    binding_id = safe_binding_identifier(binding)
    if not device_token:
        return {
            "attempted": False,
            "ok": True,
            "result": "credentials_missing",
            "reason": "device_token_missing",
        }
    if not device_id:
        return {
            "attempted": False,
            "ok": True,
            "result": "credentials_missing",
            "reason": "device_id_missing",
        }
    payload = {
        "device_id": device_id,
        "home_id": home_id,
        "binding_id": binding_id,
        "netbird_peer_id": normalize_optional_string(state.get("netbird_peer_id")),
    }
    LOG.info(
        "portal reset cleanup attempted=true device_id=%s home_id=%s binding_id=%s netbird_peer_id=%s",
        device_id or "<missing>",
        home_id or "<missing>",
        log_secret_marker(binding_id),
        normalize_optional_string(state.get("netbird_peer_id")) or "<missing>",
    )
    try:
        response, url, _resolved_base = portal_request_json(
            "POST",
            "/api/agent/binding/revoke",
            state=state,
            options=load_options(),
            payload=payload,
            headers={"Authorization": f"Bearer {device_token}"},
            timeout_seconds=10,
            purpose="portal binding revoke",
        )
        if not isinstance(response, dict):
            result = "invalid_response"
            ok = False
        else:
            result = "success"
            ok = True
        LOG.info("portal reset cleanup result=%s ok=%s endpoint=%s", result, ok, sanitize_destination_url(url))
        return {"attempted": True, "ok": ok, "result": result}
    except urllib.error.HTTPError as exc:
        body = read_http_error_body(exc)
        log_upstream_result(getattr(exc, "_hometunnel_url", "/api/agent/binding/revoke"), exc.code, body)
        if exc.code in (404, 410):
            result = "already_revoked"
            ok = True
        elif exc.code in (401, 403):
            result = "unauthorized_stale_credentials"
            ok = False
        elif exc.code in (405, 501):
            result = "unsupported"
            ok = False
        elif 500 <= exc.code <= 599:
            result = "server_error"
            ok = False
        else:
            result = "invalid_response"
            ok = False
        LOG.info("portal reset cleanup result=%s ok=%s status=%s", result, ok, exc.code)
        return {"attempted": True, "ok": ok, "result": result, "status": exc.code}
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
        LOG.info("portal reset cleanup result=network_error ok=false error=%s", sanitize_error_text(exc, secret_source=state))
        return {"attempted": True, "ok": False, "result": "network_error"}
    except Exception as exc:
        LOG.info("portal reset cleanup result=invalid_response ok=false error=%s", sanitize_error_text(exc, secret_source=state))
        return {"attempted": True, "ok": False, "result": "invalid_response"}


def ensure_netbird_daemon(options: Dict[str, Any]) -> tuple[bool, str]:
    daemon_pid = read_daemon_pid()
    if daemon_pid and pid_is_running(daemon_pid) and NETBIRD_SOCKET_PATH.exists():
        return True, "ok"

    clear_daemon_pid()
    try:
        NETBIRD_SOCKET_PATH.unlink()
    except FileNotFoundError:
        pass

    proc = subprocess.Popen(
        [
            "netbird",
            *netbird_base_args(),
            "--log-file",
            "console",
            "--log-level",
            str(options.get("log_level") or "info"),
            "service",
            "run",
        ],
        stdout=sys.stdout,
        stderr=sys.stderr,
        start_new_session=True,
    )
    write_daemon_pid(proc.pid)

    deadline = time.time() + NETBIRD_READY_TIMEOUT_SECONDS
    while time.time() < deadline:
        if proc.poll() is not None:
            clear_daemon_pid()
            return False, f"daemon_exit_{proc.returncode}"
        rc, _, _ = run_command(netbird_command("service", "status"), timeout_seconds=5)
        if rc == 0 and NETBIRD_SOCKET_PATH.exists():
            chmod_if_exists(NETBIRD_SOCKET_PATH, 0o600)
            chmod_if_exists(NETBIRD_CONFIG_PATH, 0o600)
            return True, "ok"
        time.sleep(0.5)

    return False, "daemon_ready_timeout"


def set_agent_runtime_state(agent_running: bool, last_error: Optional[str] = None) -> None:
    latest_state = read_state_snapshot()
    latest_state["agent_running"] = agent_running
    if last_error is not None:
        latest_state["last_error"] = sanitize_error_text(last_error, secret_source=latest_state)
    write_json_file(STATE_PATH, latest_state)


def update_last_error(message: Optional[str]) -> None:
    latest_state = read_state_snapshot()
    safe_message = sanitize_error_text(message, secret_source=latest_state) if message is not None else None
    latest_state["last_error"] = safe_message
    write_json_file(STATE_PATH, latest_state)
    with _state_lock:
        _state["last_error"] = safe_message


def refresh_runtime_state() -> Dict[str, Any]:
    options = load_options()
    original = read_state_snapshot()
    state = status_view_from_state(original, options)
    state["agent_running"] = is_netbird_agent_running()
    if stable_json_dumps(state) == stable_json_dumps(original):
        LOG.debug("runtime state refresh skipped unchanged paired=%s agent_running=%s", state.get("paired"), state.get("agent_running"))
        return state
    write_json_file(STATE_PATH, state)
    with _state_lock:
        _state.clear()
        _state.update(state)
    return state


def live_runtime_view(options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    latest_options = options or load_options()
    current = refresh_runtime_state()
    live_status = collect_netbird_status()
    if not normalize_optional_string(live_status.get("peer_name")):
        live_status["peer_name"] = normalize_optional_string(current.get("peer_name"))
    route_state = refresh_route_runtime_state(latest_options, live_status)
    view = status_view_from_state(
        {
            **current,
            "netbird": {**dict(current.get("netbird") or {}), **live_status},
            "route": {**dict(current.get("route") or {}), **route_state},
            "agent_running": is_netbird_agent_running(),
        },
        latest_options,
    )
    return view


def persist_runtime_observations(options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    latest_options = options or load_options()
    live_state = live_runtime_view(latest_options)
    reported_at = now_iso()
    health_report = build_health_report(dict(live_state.get("netbird") or {}), live_state, latest_options, reported_at=reported_at)

    def mutate(current: Dict[str, Any]) -> None:
        next_state = status_view_from_state(
            {
                **current,
                "netbird": dict(live_state.get("netbird") or {}),
                "route": dict(live_state.get("route") or {}),
                "agent_running": live_state.get("agent_running"),
            },
            latest_options,
        )
        current.clear()
        current.update(next_state)
        current["last_health_check_at"] = health_report.get("last_health_check_at")
        current["last_health_result"] = health_report.get("last_health_result")

    update_state(mutate)
    return refresh_runtime_state()


def wait_for_agent_running(timeout_seconds: int = 15) -> bool:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if is_netbird_agent_running():
            refresh_runtime_state()
            return True
        time.sleep(0.5)
    refresh_runtime_state()
    return False


def start_netbird_agent_if_needed() -> bool:
    with exclusive_file_lock(NETBIRD_AGENT_START_LOCK_PATH):
        return start_netbird_agent_if_needed_locked()


def start_netbird_agent_if_needed_locked() -> bool:
    invalidate_runtime_caches("start_netbird_agent")
    state_snapshot = refresh_runtime_state()
    refresh_route_runtime_state(load_options(), dict(state_snapshot.get("netbird") or {}))
    state_snapshot = refresh_runtime_state()
    if not netbird_binary_path():
        update_last_error("netbird binary not found")
        return False
    missing_reason = missing_enrollment_reason(state_snapshot)
    if missing_reason:
        update_last_error(missing_reason)
        return False
    if is_private_management_url(str(state_snapshot.get("management_url") or "")):
        update_last_error("management_url_not_public_todo")
        return False

    if is_netbird_agent_running():
        update_last_error(None)
        return False

    proc = subprocess.Popen(
        [sys.executable, "/opt/hometunnel/app.py", "--netbird-agent"],
        stdout=sys.stdout,
        stderr=sys.stderr,
        start_new_session=True,
    )
    write_agent_pid(proc.pid)
    if pid_is_running(proc.pid):
        set_agent_runtime_state(True, None)
        return True
    update_last_error("failed to launch agent supervisor")
    return False


def ensure_netbird_ready_or_connected(state: Dict[str, Any], options: Dict[str, Any]) -> tuple[bool, str, Dict[str, Any], bool]:
    with exclusive_file_lock(NETBIRD_UP_LOCK_PATH):
        daemon_ok, daemon_message = ensure_netbird_daemon(options)
        if not daemon_ok:
            return False, f"netbird_daemon_failed:{daemon_message}", {}, False
        status = collect_netbird_status()
        status["peer_name"] = str(status.get("peer_name") or state.get("peer_name") or "")
        if status.get("connected"):
            return True, "already_connected", status, False
        ok, message = netbird_up(state, options)
        return ok, message, status, True


def netbird_up(state: Dict[str, Any], options: Dict[str, Any]) -> tuple[bool, str]:
    invalidate_runtime_caches("netbird_up")
    management_url = str(state.get("management_url") or "")
    setup_key = str(state.get("setup_key") or "")
    peer_name = str(state.get("peer_name") or "")
    binding = normalize_binding_state(state)
    extra_dns_labels = effective_binding_labels(state)
    configured_dns_mode = normalize_dns_mode(options.get("dns_mode") if isinstance(options, dict) else None)
    resolved_dns_mode = effective_dns_mode(options)
    if not management_url or not setup_key:
        return False, "missing netbird credentials"
    if not netbird_binary_path():
        return False, "netbird binary not found"

    args = [
        "netbird",
        *netbird_base_args(),
        "--management-url",
        management_url,
        "--setup-key",
        setup_key,
        "--log-file",
        "console",
        "--log-level",
        str(options.get("log_level") or "info"),
        "up",
    ]
    if peer_name:
        args.extend(["--hostname", peer_name])
    if extra_dns_labels:
        args.extend(["--extra-dns-labels", ",".join(extra_dns_labels)])
    if resolved_dns_mode == "off":
        args.append("--disable-dns")
    resolver_snapshot = read_resolver_diagnostics()
    LOG.info(
        "netbird dns configuration configured=%s effective=%s nameservers=%s binding_status=%s expected_label=%s labels=%s",
        configured_dns_mode,
        resolved_dns_mode,
        ",".join(resolver_snapshot.get("nameservers") or []) or "<none>",
        binding.get("status"),
        binding.get("expected_netbird_label") or "<missing>",
        ",".join(extra_dns_labels) or "<none>",
    )
    if binding.get("status") in {"missing", "invalid"}:
        LOG.warning(
            "missing binding before netbird up device_id=%s home_id=%s status=%s validation_error=%s missing_fields=%s",
            state.get("device_id") or "<missing>",
            state.get("home_id") or "<missing>",
            binding.get("status"),
            binding.get("validation_error") or "<none>",
            ",".join(binding.get("missing_fields") or []) or "<none>",
        )

    rc, out, err = run_command(args, timeout_seconds=45)
    desired_routes = desired_advertise_routes(state, options)
    if rc == 0:
        chmod_if_exists(NETBIRD_CONFIG_PATH, 0o600)
        def mark_netbird_startup_success(current: Dict[str, Any]) -> None:
            current.setdefault("route", {}).update(
                {
                    "healthy": bool(current.get("route", {}).get("target_reachable")),
                    "last_error": None if current.get("route", {}).get("target_reachable") else current.get("route", {}).get("last_error"),
                }
            )
            current_binding = normalize_binding_state(current)
            current_binding["netbird_label_apply_status"] = "applied" if extra_dns_labels else "missing_label"
            current["binding"] = current_binding
            clear_setup_key_artifacts(current)
            current["recovery_state"] = None
            current["last_error"] = None

        update_state(mark_netbird_startup_success)
        LOG.info("netbird peer startup complete desired_routes_reported=%s", desired_routes or "<none>")
        return True, "ok"
    failure = format_netbird_up_error(err or out or "failed")
    join_failure = classify_setup_key_join_failure(failure)
    def mark_netbird_startup_failure(current: Dict[str, Any]) -> None:
        current.setdefault("route", {}).update(
            {
                "healthy": False,
                "last_error": failure,
            }
        )
        current_binding = normalize_binding_state(current)
        if extra_dns_labels:
            current_binding["netbird_label_apply_status"] = "apply_failed"
        current["binding"] = current_binding
        if join_failure == "setup_key_rejected":
            clear_setup_key_artifacts(current)
            current["recovery_state"] = "re_pair_required"
            current["last_error"] = "re_pair_required"
        elif not normalize_optional_string(current.get("last_error")):
            current["last_error"] = failure

    update_state(mark_netbird_startup_failure)
    LOG.warning("netbird peer startup failed desired_routes_reported=%s error=%s", desired_routes or "<none>", failure)
    return False, failure


def send_heartbeat(status: Dict[str, Any], state: Dict[str, Any], options: Dict[str, Any]) -> Optional[str]:
    device_token = state.get("device_token")
    device_id = state.get("device_id")
    home_id = state.get("home_id")
    if not device_token or not device_id or not home_id:
        LOG.debug(
            "ha route heartbeat skipped reason=missing_credentials device_id=%s home_id=%s has_token=%s",
            device_id or "<missing>",
            home_id or "<missing>",
            bool(device_token),
        )
        return None

    heartbeat_path = f"/api/devices/{urllib.parse.quote(str(device_id))}/heartbeat"
    route_state = dict(state.get("route") or {})
    binding = normalize_binding_state(state)
    binding_id = safe_binding_identifier(binding)
    has_binding_token = binding_token_present(binding)
    binding_updated_at = binding_last_update_at(binding)
    peer_id = normalize_optional_string(state.get("netbird_peer_id"))
    local_status_peer_id = normalize_optional_string(status.get("peer_id"))
    wireguard_public_key = normalize_optional_string(status.get("wireguard_public_key"))
    if not binding_id:
        LOG.warning(
            "ha route heartbeat skipped reason=missing_binding_id device_id=%s home_id=%s peer_id=%s binding_id=%s binding_token_present=%s",
            device_id or "<missing>",
            home_id or "<missing>",
            peer_id or local_status_peer_id or "<unknown>",
            "<missing>",
            has_binding_token,
        )
        update_state(
            lambda current: current.update(
                {
                    "heartbeat_error": "missing_binding_id",
                    "last_health_report_error": "missing_binding_id",
                    "last_error": "missing_binding_id",
                    "recovery_state": None,
                }
            )
        )
        return "missing_binding_id"
    if not peer_id:
        try:
            peer_id = fetch_device_config(state, options)
            if peer_id:
                state = read_json_file(STATE_PATH, state)
                LOG.info(
                    "device config recovered netbird management peer id device_id=%s home_id=%s peer_id=%s",
                    device_id or "<missing>",
                    home_id or "<missing>",
                    peer_id,
                )
        except urllib.error.HTTPError as exc:
            failed_url = getattr(exc, "_hometunnel_url", None)
            body = read_http_error_body(exc)
            log_upstream_result(failed_url or f"/api/devices/{device_id}/config", exc.code, body)
            LOG.warning(
                "device config fetch failed device_id=%s home_id=%s status=%s reason=%s",
                device_id or "<missing>",
                home_id or "<missing>",
                exc.code,
                sanitize_error_text(body or exc, secret_source=state),
            )
        except Exception as exc:
            LOG.warning(
                "device config fetch failed device_id=%s home_id=%s reason=%s",
                device_id or "<missing>",
                home_id or "<missing>",
                sanitize_error_text(exc, secret_source=state),
            )
    if not peer_id:
        LOG.warning(
            "ha route heartbeat skipped reason=netbird_management_peer_id_missing device_id=%s home_id=%s local_status_peer_id=%s wireguard_public_key_present=%s binding_id=%s binding_token_present=%s",
            device_id or "<missing>",
            home_id or "<missing>",
            local_status_peer_id or "<none>",
            bool(wireguard_public_key),
            log_secret_marker(binding_id),
            has_binding_token,
        )
        update_state(
            lambda current: current.update(
                {
                    "heartbeat_error": "netbird_management_peer_id_missing",
                    "last_health_report_error": "netbird_management_peer_id_missing",
                    "last_error": "netbird_management_peer_id_missing",
                }
            )
        )
        return "netbird_management_peer_id_missing"
    reported_at = now_iso()
    health_report = build_health_report(status, state, options, reported_at=reported_at)
    payload = build_heartbeat_payload(status, state)
    route_refresh_gaps = heartbeat_telemetry_gaps(route_state)
    network_payload = dict(payload.get("network") or {})
    target_payload = dict(payload.get("target") or {})
    target_observation = dict(payload.get("targetObservation") or {})
    observed_target_ip = target_observation.get("observedTargetIp") or target_payload.get("targetIp")
    observed_target_hostname = target_observation.get("observedTargetHostname") or target_payload.get("targetHostname")
    LOG.debug(
        "heartbeat_target_observation_built device_id=%s home_id=%s peer_id=%s action=telemetry reason=%s observed_target_ip=%s observed_target_hostname=%s",
        device_id or "<missing>",
        home_id or "<missing>",
        peer_id or "<unknown>",
        current_target_resolution_state(route_state),
        observed_target_ip or "<unknown>",
        observed_target_hostname or "<unknown>",
    )
    if network_payload.get("sameLanDetected"):
        LOG.info(
            "same_lan_detected device_id=%s home_id=%s peer_id=%s action=telemetry reason=%s target_ip=%s local_ipv4_subnets=%s",
            device_id or "<missing>",
            home_id or "<missing>",
            peer_id or "<unknown>",
            network_payload.get("localBypassReason") or network_payload.get("networkStatus") or "same_lan",
            observed_target_ip or "<unknown>",
            ",".join(network_payload.get("localIPv4Subnets") or []) or "<none>",
        )
    if network_payload.get("exactIpConflict"):
        LOG.info(
            "exact_ip_conflict_detected device_id=%s home_id=%s peer_id=%s action=telemetry reason=%s target_ip=%s local_ipv4_addresses=%s",
            device_id or "<missing>",
            home_id or "<missing>",
            peer_id or "<unknown>",
            network_payload.get("localBypassReason") or "exact_ip_conflict",
            observed_target_ip or "<unknown>",
            ",".join(network_payload.get("localIPv4Addresses") or []) or "<none>",
        )
    if network_payload.get("subnetOverlap"):
        LOG.info(
            "subnet_overlap_detected device_id=%s home_id=%s peer_id=%s action=telemetry reason=%s target_ip=%s matching_subnets=%s",
            device_id or "<missing>",
            home_id or "<missing>",
            peer_id or "<unknown>",
            network_payload.get("localBypassReason") or network_payload.get("networkStatus") or "subnet_overlap",
            observed_target_ip or "<unknown>",
            ",".join(network_payload.get("matchingLocalSubnets") or []) or "<none>",
        )
    if network_payload.get("localBypassRecommended"):
        LOG.info(
            "local_bypass_recommended device_id=%s home_id=%s peer_id=%s action=telemetry reason=%s target_ip=%s",
            device_id or "<missing>",
            home_id or "<missing>",
            peer_id or "<unknown>",
            network_payload.get("localBypassReason") or "same_lan",
            observed_target_ip or "<unknown>",
        )
    if any(reason.startswith("target_observation:") for reason in route_refresh_gaps) or not observed_target_ip:
        LOG.warning(
            "heartbeat_payload_missing_target_observation device_id=%s home_id=%s peer_id=%s action=telemetry reason=%s",
            device_id or "<missing>",
            home_id or "<missing>",
            peer_id or "<unknown>",
            ",".join(route_refresh_gaps) or current_target_resolution_state(route_state),
        )
    if network_payload.get("localIPv4Addresses") or network_payload.get("localIPv4Subnets"):
        LOG.debug(
            "heartbeat_network_state_built device_id=%s home_id=%s peer_id=%s action=telemetry reason=%s",
            device_id or "<missing>",
            home_id or "<missing>",
            peer_id or "<unknown>",
            network_payload.get("networkStatus") or "observed",
        )
    else:
        LOG.warning(
            "heartbeat_network_state_missing device_id=%s home_id=%s peer_id=%s action=telemetry reason=%s",
            device_id or "<missing>",
            home_id or "<missing>",
            peer_id or "<unknown>",
            route_state.get("local_ipv4_error") or route_state.get("local_ipv4_source") or "unavailable",
        )
    if route_refresh_gaps:
        LOG.info(
            "heartbeat_network_state_built device_id=%s home_id=%s peer_id=%s action=force_send reason=%s",
            device_id or "<missing>",
            home_id or "<missing>",
            peer_id or "<unknown>",
            ",".join(route_refresh_gaps),
        )
    if bool(state.get("paired")) and (binding.get("status") in {"missing", "partial", "invalid"} or not binding_id):
        LOG.warning(
            "heartbeat binding material incomplete device_id=%s home_id=%s binding_id=%s binding_token_present=%s last_enrollment_update_at=%s status=%s validation_error=%s missing_fields=%s",
            device_id or "<missing>",
            home_id or "<missing>",
            log_secret_marker(binding_id),
            has_binding_token,
            binding_updated_at or "<none>",
            binding.get("status"),
            binding.get("validation_error") or "<none>",
            ",".join(binding.get("missing_fields") or []) or "<none>",
        )
    payload_fingerprint = heartbeat_fingerprint(payload, state)
    log_heartbeat_payload(payload)
    now_monotonic = time.monotonic()
    steady_state_interval_seconds = max(HEALTH_REPORT_INTERVAL_SECONDS, HEARTBEAT_UNCHANGED_MIN_SECONDS)
    with _heartbeat_lock:
        cached_fingerprint = _heartbeat_cache.get("fingerprint")
        cached_sent_at = float(_heartbeat_cache.get("sent_at") or 0.0)
    unchanged_age_seconds = now_monotonic - cached_sent_at
    force_telemetry_refresh = bool(route_refresh_gaps)
    if (
        payload_fingerprint == cached_fingerprint
        and not bool(route_state.get("needs_report"))
        and not force_telemetry_refresh
        and unchanged_age_seconds < steady_state_interval_seconds
    ):
        LOG.debug(
            "ha route heartbeat skipped unchanged age_seconds=%.1f endpoint=%s health_interval_seconds=%s cache_decision=skip binding_id=%s binding_token_present=%s heartbeat_url_device_id=%s last_enrollment_update_at=%s",
            unchanged_age_seconds,
            route_state.get("current_endpoint"),
            int(steady_state_interval_seconds),
            log_secret_marker(binding_id),
            has_binding_token,
            device_id or "<missing>",
            binding_updated_at or "<none>",
        )
        return None
    report_reason = "periodic_health"
    if payload_fingerprint != cached_fingerprint:
        report_reason = "state_changed"
    elif bool(route_state.get("needs_report")):
        report_reason = "route_reconcile_pending"
    LOG.info(
        "ha route heartbeat queued reason=%s endpoint=%s target_ip=%s peer_ip=%s needs_report=%s connected=%s binding_status=%s cache_decision=send binding_id=%s binding_token_present=%s heartbeat_url_device_id=%s last_enrollment_update_at=%s",
        report_reason,
        route_state.get("current_endpoint"),
        route_state.get("target_ip"),
        status.get("peer_ip"),
        route_state.get("needs_report"),
        status.get("connected"),
        binding.get("status"),
        log_secret_marker(binding_id),
        has_binding_token,
        device_id or "<missing>",
        binding_updated_at or "<none>",
    )
    LOG.info(
        "binding presented on heartbeat device_id=%s home_id=%s binding_id=%s expected_label=%s missing_fields=%s has_signed_token=%s",
        device_id,
        home_id,
        log_secret_marker(binding_id, missing="<none>"),
        binding.get("expected_netbird_label") or "<missing>",
        ",".join(binding.get("missing_fields") or []) or "<none>",
        has_binding_token,
    )
    try:
        response, url, resolved_base = portal_request_json(
            "POST",
            heartbeat_path,
            state=state,
            options=options,
            payload=payload,
            headers={"Authorization": f"Bearer {device_token}"},
            purpose="ha route heartbeat",
        )
        latest_state = read_json_file(STATE_PATH, default_state())
        clear_setup_key_artifacts(latest_state)
        latest_state["netbird"] = {
            **dict(latest_state.get("netbird") or {}),
            "connected": bool(status.get("connected")),
            "peer_id": status.get("peer_id"),
            "wireguard_public_key": status.get("wireguard_public_key"),
            "peer_ip": status.get("peer_ip"),
            "peer_name": status.get("peer_name") or state.get("peer_name"),
            "remote_peers": status.get("remote_peers") or latest_state.get("netbird", {}).get("remote_peers", []),
            "raw": status.get("raw"),
        }
        latest_state["route"] = {
            **dict(latest_state.get("route") or {}),
            **route_state,
        }
        next_home_access_mode = extract_home_access_mode_from_response(response)
        if next_home_access_mode:
            latest_state.setdefault("route", {})["ha_access_mode"] = next_home_access_mode
        hometunnel_identity = route_state.get("hometunnel_dns_hostname") or build_hometunnel_dns_hostname(device_id, home_id)
        effective_target_hostname = route_state.get("effective_target_hostname") or route_state.get("target_hostname")
        resolved_target_hostname = route_state.get("resolved_target_hostname") or route_state.get("target_hostname")
        latest_state.setdefault("route", {}).update(
            {
                "effective_target_hostname": effective_target_hostname,
                "resolved_target_hostname": resolved_target_hostname,
                "hometunnel_dns_hostname": hometunnel_identity,
                "hometunnel_display_identity": route_state.get("hometunnel_display_identity") or hometunnel_identity,
                "overlay_identity": route_state.get("overlay_identity") or hometunnel_identity,
                "overlay_identity_basis": route_state.get("overlay_identity_basis") or hometunnel_identity,
                "effective_target_identity": route_state.get("effective_target_identity") or effective_target_hostname,
                "effective_target_cidr": route_state.get("effective_target_cidr"),
            }
        )
        latest_state["last_heartbeat_at"] = reported_at
        latest_state["last_heartbeat_result"] = {"ok": response.get("ok", True)}
        latest_state["last_heartbeat_destination"] = sanitize_destination_url(url)
        latest_state["heartbeat_error"] = None
        latest_state["recovery_state"] = None
        latest_state["last_health_check_at"] = health_report.get("last_health_check_at")
        latest_state["last_agent_report_at"] = health_report.get("last_agent_report_at")
        latest_state["last_health_result"] = health_report.get("last_health_result")
        latest_state["last_health_report_error"] = None
        latest_state["portal_base_url"] = resolved_base
        latest_state["last_error"] = None
        latest_binding = normalize_binding_state(latest_state)
        latest_binding["presented_at"] = reported_at
        latest_state["binding"] = latest_binding
        apply_portal_binding_validation_result(latest_state, response, reported_at=reported_at)
        extracted = extract_route_status_from_response(response)
        latest_state.setdefault("route", {}).update(
            {
                "route_ids": extracted["route_ids"] or latest_state.get("route", {}).get("route_ids", []),
                "peer_group_ids": extracted["peer_group_ids"] or latest_state.get("route", {}).get("peer_group_ids", []),
                "policy_ids": extracted["policy_ids"] or latest_state.get("route", {}).get("policy_ids", []),
                "applied_advertise_routes": extracted["applied_advertise_routes"] or latest_state.get("route", {}).get("applied_advertise_routes"),
                "healthy": extracted["healthy"] if extracted["route_ids"] or extracted["policy_ids"] else latest_state.get("route", {}).get("healthy"),
                "last_error": extracted["last_error"] or latest_state.get("route", {}).get("last_error"),
                "needs_report": False,
                "last_reconciled_at": now_iso(),
            }
        )
        latest_state = status_view_from_state(latest_state, options)
        write_json_file(STATE_PATH, latest_state)
        with _heartbeat_lock:
            _heartbeat_cache["fingerprint"] = payload_fingerprint
            _heartbeat_cache["sent_at"] = now_monotonic
        LOG.info(
            "ha route heartbeat success endpoint=%s target_ip=%s desired_routes=%s applied_routes=%s local_tcp_8123=%s health=%s last_agent_report_at=%s",
            route_state.get("current_endpoint"),
            route_state.get("target_ip"),
            route_state.get("desired_advertise_routes") or "<none>",
            extracted["applied_advertise_routes"] or route_state.get("applied_advertise_routes") or "<none>",
            route_state.get("local_tcp_8123_reachable"),
            route_state.get("health_status"),
            health_report.get("last_agent_report_at"),
        )
        return None
    except urllib.error.HTTPError as exc:
        failed_url = getattr(exc, "_hometunnel_url", None)
        body = read_http_error_body(exc)
        classification = classify_heartbeat_failure(exc.code, body)
        degrade_connected_failure = should_degrade_connected_heartbeat_failure(status, classification)
        log_upstream_result(failed_url or heartbeat_path, exc.code, body)
        LOG.warning(
            "heartbeat_send_failed device_id=%s home_id=%s peer_id=%s action=portal_request status=%s reason=%s recovery_state=%s destructive=%s clear_binding=%s clear_device_token=%s error=%s",
            device_id or "<missing>",
            home_id or "<missing>",
            peer_id or "<unknown>",
            exc.code,
            classification["error_code"],
            "portal_trust_degraded" if degrade_connected_failure else classification["recovery_state"] or "<none>",
            bool(classification.get("destructive")),
            bool(classification.get("clear_binding")),
            bool(classification.get("clear_device_token")),
            exc,
        )
        update_state(
            lambda current: current.update(
                {
                    **(
                        {"last_heartbeat_destination": sanitize_destination_url(failed_url)}
                        if failed_url
                        else {}
                    ),
                    "last_health_check_at": health_report.get("last_health_check_at"),
                    "last_health_result": health_report.get("last_health_result"),
                    "last_health_report_error": classification["error_code"],
                    "heartbeat_error": "heartbeat_auth_failed" if degrade_connected_failure else classification["error_code"],
                    "last_error": "heartbeat_auth_failed"
                    if degrade_connected_failure
                    else classification["error_code"],
                    "recovery_state": None if degrade_connected_failure else classification["recovery_state"],
                }
            )
        )
        if classification["clear_binding"] and not degrade_connected_failure:
            update_state(
                lambda current: current.update(
                    {
                        "binding": normalize_binding_state(
                            {
                                **current,
                                "binding": merge_binding_sources(
                                    current.get("binding"),
                                    {
                                        "portal_validation_error": classification["error_code"],
                                        "portal_validation_reported_at": reported_at,
                                    },
                                    clear_keys={"binding_id", "device_binding_id", "signed_binding_token"},
                                ),
                            }
                        )
                    }
                )
            )
        if classification["clear_device_token"] and not degrade_connected_failure:
            update_state(lambda current: current.update({"device_token": None}))
        if classification["clear_setup_key"] and not degrade_connected_failure:
            update_state(lambda current: clear_setup_key_artifacts(current))
        return classification["error_code"]
    except Exception as exc:
        failed_url = getattr(exc, "_hometunnel_url", None)
        failed_host = urllib.parse.urlsplit(failed_url).hostname if failed_url else None
        safe_error = sanitize_error_text(exc, secret_source=state)
        LOG.warning(
            "heartbeat_send_failed device_id=%s home_id=%s peer_id=%s action=portal_request status=%s host=%s resolved_base_url=%s reason=%s",
            device_id or "<missing>",
            home_id or "<missing>",
            peer_id or "<unknown>",
            "n/a",
            failed_host or "<unknown>",
            sanitize_destination_url(failed_url) if failed_url else "<unknown>",
            safe_error,
        )
        heartbeat_error = f"heartbeat_error:{safe_error}"
        update_state(
            lambda current: current.update(
                {
                    **(
                        {"last_heartbeat_destination": sanitize_destination_url(failed_url)}
                        if failed_url
                        else {}
                    ),
                    "last_health_check_at": health_report.get("last_health_check_at"),
                    "last_health_result": health_report.get("last_health_result"),
                    "last_health_report_error": heartbeat_error,
                    "heartbeat_error": heartbeat_error,
                    "last_error": heartbeat_error,
                }
            )
        )
        return heartbeat_error


def netbird_agent_loop() -> int:
    ensure_data_dir()
    write_agent_pid(os.getpid())
    set_agent_runtime_state(True, None)

    def handle_signal(_signum, _frame) -> None:
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    backoff_seconds = NETBIRD_RETRY_MIN_SECONDS
    last_netbird_up_attempt_at = 0.0
    try:
        while True:
            state = read_json_file(STATE_PATH, default_state())
            options = load_options()
            route_state = refresh_route_runtime_state(options, dict(state.get("netbird") or {}))
            with exclusive_file_lock(NETBIRD_UP_LOCK_PATH):
                daemon_ok, daemon_message = ensure_netbird_daemon(options)
                status = collect_netbird_status() if daemon_ok else {}
            if not daemon_ok:
                set_agent_runtime_state(False, f"netbird_daemon_failed:{daemon_message}")
                time.sleep(backoff_seconds)
                backoff_seconds = min(backoff_seconds * 2, NETBIRD_RETRY_MAX_SECONDS)
                continue

            status["peer_name"] = str(status.get("peer_name") or state.get("peer_name") or "")
            if bool(state.get("agent_running")) is True and dict(state.get("netbird") or {}) == status:
                LOG.debug("netbird agent state persistence skipped unchanged connected=%s", status.get("connected"))
            else:
                state["agent_running"] = True
                state["netbird"] = status
                write_json_file(STATE_PATH, state)
            route_state = refresh_route_runtime_state(options, status)
            state = read_json_file(STATE_PATH, default_state())

            if not has_netbird_credentials(state):
                time.sleep(NETBIRD_RETRY_MIN_SECONDS)
                continue
            recovery_state = normalize_optional_string(state.get("recovery_state"))
            if recovery_state in NON_RETRYABLE_RECOVERY_STATES:
                LOG.info(
                    "ha route recovery paused reason=%s peer_id=%s peer_ip=%s route_target=%s",
                    recovery_state,
                    status.get("peer_id") or "<unknown>",
                    status.get("peer_ip") or "<unknown>",
                    route_state.get("current_endpoint") or "<unknown>",
                )
                time.sleep(POLL_INTERVAL_SECONDS)
                continue

            desired_routes = desired_advertise_routes(state, options)
            applied_routes = str((state.get("route") or {}).get("applied_advertise_routes") or "")
            if status.get("connected"):
                if bool(route_state.get("needs_report")) or desired_routes != applied_routes:
                    LOG.info(
                        "ha route update pending portal reconciliation desired=%s applied=%s access_mode=%s",
                        desired_routes or "<none>",
                        applied_routes or "<none>",
                        route_state.get("access_mode"),
                    )
                heartbeat_error = send_heartbeat(status, state, options)
                if heartbeat_error:
                    state = read_json_file(STATE_PATH, default_state())
                    heartbeat_error = sanitize_error_text(heartbeat_error, secret_source=state)
                    state["heartbeat_error"] = heartbeat_error
                    if not normalize_optional_string(state.get("last_error")):
                        state["last_error"] = heartbeat_error
                    write_json_file(STATE_PATH, state)
                backoff_seconds = NETBIRD_RETRY_MIN_SECONDS
                time.sleep(POLL_INTERVAL_SECONDS)
                continue
            LOG.info(
                "ha route heartbeat skipped reason=netbird_not_connected peer_id=%s peer_ip=%s route_target=%s",
                status.get("peer_id") or "<unknown>",
                status.get("peer_ip") or "<unknown>",
                route_state.get("current_endpoint") or "<unknown>",
            )

            if not options.get("always_on", True):
                time.sleep(POLL_INTERVAL_SECONDS)
                continue

            now_monotonic = time.monotonic()
            if now_monotonic - last_netbird_up_attempt_at < NETBIRD_UP_DEBOUNCE_SECONDS:
                time.sleep(NETBIRD_UP_DEBOUNCE_SECONDS)
                continue
            last_netbird_up_attempt_at = now_monotonic
            ok, message, latest_status, attempted_up = ensure_netbird_ready_or_connected(state, options)
            if latest_status.get("connected"):
                latest_state = read_json_file(STATE_PATH, default_state())
                latest_state["agent_running"] = True
                latest_state["netbird"] = latest_status
                latest_state["last_error"] = None
                write_json_file(STATE_PATH, latest_state)
                backoff_seconds = NETBIRD_RETRY_MIN_SECONDS
                time.sleep(POLL_INTERVAL_SECONDS)
                continue
            latest_state = read_json_file(STATE_PATH, default_state())
            latest_state["agent_running"] = True
            if ok:
                latest_state["last_error"] = None
            elif not normalize_optional_string(latest_state.get("last_error")):
                latest_state["last_error"] = f"netbird_up_failed:{sanitize_error_text(message, secret_source=latest_state)}"
            write_json_file(STATE_PATH, latest_state)

            if ok and attempted_up:
                backoff_seconds = NETBIRD_RETRY_MIN_SECONDS
                time.sleep(NETBIRD_RETRY_MIN_SECONDS)
            elif ok:
                backoff_seconds = NETBIRD_RETRY_MIN_SECONDS
                time.sleep(POLL_INTERVAL_SECONDS)
            else:
                time.sleep(backoff_seconds)
                backoff_seconds = min(backoff_seconds * 2, NETBIRD_RETRY_MAX_SECONDS)
    finally:
        stop_netbird_daemon()
        set_agent_runtime_state(False, None)
        clear_agent_pid()


def ui_refresh_loop() -> None:
    while not _stop_event.is_set():
        state = refresh_runtime_state()
        if bool(state.get("agent_running")):
            LOG.debug("ui refresh live status skipped while netbird agent loop is active")
        else:
            state = persist_runtime_observations(load_options())
            if not state:
                LOG.debug("ui refresh persistence skipped empty state")
        _stop_event.wait(POLL_INTERVAL_SECONDS)


def redact_state(state: Dict[str, Any]) -> Dict[str, Any]:
    state_copy = clone_json(state)
    sanitize_state_error_fields(state_copy)
    state_copy["setup_key"] = "***redacted***" if state_copy.get("setup_key") else None
    state_copy["device_token"] = "***redacted***" if state_copy.get("device_token") else None
    binding = dict(state_copy.get("binding") or {})
    if binding.get("signed_binding_token"):
        binding["signed_binding_token"] = "***redacted***"
    state_copy["binding"] = binding
    if isinstance(state_copy.get("last_heartbeat_result"), dict):
        state_copy["last_heartbeat_result"] = {"ok": state_copy["last_heartbeat_result"].get("ok")}
    return state_copy


def iso_from_expires_in(expires_in: Any) -> Optional[str]:
    try:
        seconds = int(expires_in)
    except Exception:
        return None
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


def enroll_retry_after_iso(device_auth: Dict[str, Any]) -> str:
    try:
        poll_interval = int(device_auth.get("poll_interval") or 5)
    except Exception:
        poll_interval = 5
    retry_seconds = min(60, max(5, poll_interval))
    return (datetime.now(timezone.utc) + timedelta(seconds=retry_seconds)).isoformat()


def normalize_base_url(url: str) -> Optional[str]:
    value = str(url or "").strip()
    if not value:
        return None
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    normalized_path = parsed.path.rstrip("/")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, normalized_path, "", ""))


def pairing_session_response_payload(state: Dict[str, Any], *, reused: bool = False) -> Dict[str, Any]:
    session = normalize_pairing_session_state(state)
    payload = {
        "ok": True,
        "status": session.get("pairing_status") or ("starting" if session.get("pairing_inflight") else None),
        "device_code": session.get("device_code"),
        "user_code": session.get("user_code"),
        "verification_url": session.get("verification_url"),
        "expires_at": session.get("pairing_expires_at"),
        "expires_in": pairing_session_remaining_seconds(session),
        "interval": session.get("poll_interval") or 5,
        "pairing_started_at": session.get("pairing_started_at"),
        "pairing_expires_at": session.get("pairing_expires_at"),
        "pairing_inflight": bool(session.get("pairing_inflight")),
        "pairing_start_allowed": bool(state.get("pairing_start_allowed")),
        "pairing_start_blocked_reason": state.get("pairing_start_blocked_reason"),
        "reused": reused,
    }
    return payload


def run_pairing_start_request(local_device_id: str, started_at: str) -> None:
    try:
        latest_options = load_options()
        state_snapshot = status_view_from_state(read_state_snapshot(), latest_options)
        payload = {
            "local_device_id": local_device_id,
            "device_name": build_device_name(),
            "ha_info": build_ha_info(state_snapshot, latest_options),
        }
        result, url, _resolved_base = portal_request_json(
            "POST",
            "/api/agent/device-auth/start",
            state=state_snapshot,
            options=latest_options,
            payload=payload,
            purpose="device auth start",
        )
        device_code = first_present(result, "device_code", "deviceCode")
        user_code = first_present(result, "user_code", "userCode")
        verification_url = first_present(result, "verification_url", "verificationUrl")
        try:
            poll_interval = max(1, int(first_present(result, "poll_interval", "pollInterval") or 5))
        except Exception:
            poll_interval = 5
        expires_at = pairing_deadline_iso(
            started_at,
            first_present(result, "expires_at", "expiresAt") or iso_from_expires_in(first_present(result, "expires_in", "expiresIn")),
        )
        if not device_code or not user_code or not verification_url:
            log_upstream_result(url, 200, json.dumps(result))
            raise RuntimeError("device_auth_start_invalid_response")

        def mutate(state: Dict[str, Any]) -> None:
            current = normalize_pairing_session_state(state)
            if current.get("pairing_started_at") != started_at:
                return
            state["local_device_id"] = local_device_id
            update_pairing_session_state(
                state,
                {
                    "device_code": device_code,
                    "user_code": user_code,
                    "verification_url": verification_url,
                    "pairing_started_at": started_at,
                    "pairing_expires_at": expires_at,
                    "pairing_status": "pending",
                    "pairing_inflight": False,
                    "poll_interval": poll_interval,
                },
                replace=True,
            )
            state["last_pair_check"] = None
            state["last_error"] = None

        update_state(mutate)
    except Exception as exc:
        LOG.warning("device auth start background request failed error=%s", exc)

        def mutate(state: Dict[str, Any]) -> None:
            current = normalize_pairing_session_state(state)
            if current.get("pairing_started_at") != started_at:
                return
            update_pairing_session_state(
                state,
                {
                    "device_code": None,
                    "user_code": None,
                    "verification_url": None,
                    "pairing_started_at": started_at,
                    "pairing_expires_at": None,
                    "pairing_status": "error",
                    "pairing_inflight": False,
                    "poll_interval": 5,
                },
                replace=True,
            )
            state["last_error"] = sanitize_error_text(exc, secret_source=state)

        update_state(mutate)


def proxy_rewrite_candidate_bases(current_upstream: Optional[str]) -> list[str]:
    options = load_options()
    candidates = [
        current_upstream,
        normalize_base_url(os.environ.get("HOME_ASSISTANT_URL", "")),
        normalize_base_url(str(options.get("home_assistant_url") or "")),
        normalize_base_url("http://supervisor/core"),
        normalize_base_url("http://homeassistant.local:8123"),
        normalize_base_url("http://homeassistant:8123"),
    ]
    deduped: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        deduped.append(candidate)
    return deduped


def build_target_url(base_url: str, path: str, query: str = "") -> str:
    parsed = urllib.parse.urlsplit(base_url)
    base_path = parsed.path.rstrip("/")
    request_path = "/" + path.lstrip("/")
    combined_path = f"{base_path}{request_path}" if base_path else request_path
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, combined_path or "/", query, ""))


def build_websocket_target_url(base_url: str, path: str, query: str = "") -> str:
    parsed = urllib.parse.urlsplit(base_url)
    ws_scheme = "wss" if parsed.scheme == "https" else "ws"
    return urllib.parse.urlunsplit(
        (
            ws_scheme,
            parsed.netloc,
            (parsed.path.rstrip("/") + "/" + path.lstrip("/")) if parsed.path.rstrip("/") else "/" + path.lstrip("/"),
            query,
            "",
        )
    )


def bind_check(host: str, port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
    finally:
        sock.close()


class UpstreamResolutionError(RuntimeError):
    pass


class HomeAssistantUpstreamResolver:
    def __init__(self, cache_path: Path) -> None:
        self._cache_path = cache_path
        self._lock = threading.Lock()
        self._current_url: Optional[str] = None
        self._current_source: Optional[str] = None
        self._last_resolved_at: Optional[str] = None
        self._last_error: Optional[str] = None
        self._load_cache()

    def _load_cache(self) -> None:
        cached = read_json_file(self._cache_path, {})
        cached_url = normalize_base_url(str(cached.get("last_known_good_url") or ""))
        with self._lock:
            self._current_url = cached_url
            self._current_source = "last_known_good" if cached_url else None
            self._last_resolved_at = cached.get("last_resolved_at")
            self._last_error = cached.get("last_error")
        update_proxy_runtime_state(self._current_url, self._current_source, self._last_resolved_at, self._last_error)

    def _store_cache(self, url: Optional[str], source: Optional[str], resolved_at: Optional[str], error: Optional[str]) -> None:
        payload = {
            "last_known_good_url": url,
            "last_known_good_source": source,
            "last_resolved_at": resolved_at,
            "last_error": error,
        }
        write_json_file(self._cache_path, payload)
        update_proxy_runtime_state(url, source, resolved_at, error)

    def _candidate_urls(self) -> list[tuple[str, str]]:
        options = load_options()
        configured_env = normalize_base_url(os.environ.get("HOME_ASSISTANT_URL", ""))
        configured_option = normalize_base_url(str(options.get("home_assistant_url") or ""))
        with self._lock:
            cached = self._current_url

        # Each HAOS add-on resolves its own upstream locally. Remote peers must target the
        # agent's NetBird IP on :8123; the upstream hostname is never the global routing key.
        ordered: list[tuple[str, Optional[str]]] = [
            ("configured_env", configured_env),
            ("configured_option", configured_option),
            ("homeassistant_local", normalize_base_url("http://homeassistant.local:8123")),
            ("homeassistant_service", normalize_base_url("http://homeassistant:8123")),
            # Prefer direct Home Assistant service URLs for full frontend/auth proxying.
            ("supervisor_core", normalize_base_url("http://supervisor/core")),
            ("last_known_good", cached),
        ]
        deduped: list[tuple[str, str]] = []
        seen: set[str] = set()
        for source, candidate in ordered:
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            deduped.append((source, candidate))
        return deduped

    def _probe_url(self, candidate: str, path: str, expected_statuses: set[int]) -> tuple[bool, str]:
        url = build_target_url(candidate, path)
        request = urllib.request.Request(url, headers={"Accept": "application/json,text/html;q=0.9,*/*;q=0.8"}, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=PROXY_CONNECT_TIMEOUT_SECONDS) as response:
                status = int(getattr(response, "status", 200))
                return status in expected_statuses, f"{path}:http_{status}"
        except urllib.error.HTTPError as exc:
            return exc.code in expected_statuses, f"{path}:http_{exc.code}"
        except Exception as exc:
            return False, sanitize_error_text(f"{path}:{exc}")

    def _health_check(self, candidate: str) -> tuple[bool, str]:
        auth_ready, auth_detail = self._probe_url(candidate, "/auth/providers", {200})
        if auth_ready:
            return True, auth_detail

        frontend_ready, frontend_detail = self._probe_url(candidate, "/manifest.json", {200})
        if frontend_ready:
            return True, frontend_detail

        return False, f"{auth_detail};{frontend_detail}"

    def resolve(self, force: bool = False, reason: str = "request") -> str:
        with self._lock:
            if self._current_url and not force:
                return self._current_url

        last_error = "no_candidates"
        for source, candidate in self._candidate_urls():
            healthy, detail = self._health_check(candidate)
            if healthy:
                resolved_at = now_iso()
                LOG.info("ha proxy upstream selected source=%s url=%s reason=%s detail=%s", source, candidate, reason, detail)
                with self._lock:
                    self._current_url = candidate
                    self._current_source = source
                    self._last_resolved_at = resolved_at
                    self._last_error = None
                    self._store_cache(self._current_url, self._current_source, self._last_resolved_at, self._last_error)
                    return candidate
            last_error = f"{source}:{detail}"
            LOG.warning("ha proxy upstream rejected source=%s url=%s reason=%s detail=%s", source, candidate, reason, detail)

        resolved_at = now_iso()
        with self._lock:
            self._current_url = None
            self._current_source = None
            self._last_resolved_at = resolved_at
            self._last_error = last_error
            self._store_cache(None, None, self._last_resolved_at, self._last_error)
        raise UpstreamResolutionError(last_error)

    def invalidate(self, failed_url: str, error: str) -> None:
        with self._lock:
            if failed_url != self._current_url:
                return
            self._last_error = error
            self._current_url = None
            self._current_source = None
            self._last_resolved_at = now_iso()
            self._store_cache(None, None, self._last_resolved_at, self._last_error)

    def mark_success(self, base_url: str) -> None:
        normalized = normalize_base_url(base_url)
        if not normalized:
            return
        with self._lock:
            source = self._current_source if normalized == self._current_url else "last_known_good"
            self._current_url = normalized
            self._current_source = source
            self._last_resolved_at = now_iso()
            self._last_error = None
            self._store_cache(self._current_url, self._current_source, self._last_resolved_at, self._last_error)

    def snapshot(self) -> Dict[str, Optional[str]]:
        with self._lock:
            return {
                "selected_url": self._current_url,
                "selected_source": self._current_source,
                "last_resolved_at": self._last_resolved_at,
                "last_error": self._last_error,
            }


def forwarded_headers(headers, client_host: Optional[str], scheme: str, host: str, port: Optional[int]) -> Dict[str, str]:
    forwarded: Dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in HOP_BY_HOP_HEADERS:
            continue
        forwarded[key] = value

    existing_forwarded_for = headers.get("x-forwarded-for")
    forwarded["x-forwarded-for"] = f"{existing_forwarded_for}, {client_host}" if existing_forwarded_for and client_host else (client_host or existing_forwarded_for or "")
    forwarded["x-forwarded-host"] = host
    forwarded["x-forwarded-proto"] = scheme
    if port is not None:
        forwarded["x-forwarded-port"] = str(port)
    forwarded["host"] = host
    client_authorization = headers.get("authorization")
    if client_authorization is None:
        forwarded.pop("authorization", None)
    else:
        forwarded["authorization"] = client_authorization
    client_cookie = headers.get("cookie")
    if client_cookie is not None:
        forwarded["cookie"] = client_cookie
    return {key: value for key, value in forwarded.items() if value != ""}


def public_origin_for_request(request: Request) -> str:
    host = request.headers.get("host") or request.url.netloc
    return urllib.parse.urlunsplit((request.url.scheme, host, "", "", ""))


def rewrite_upstream_location(location: str, upstream_base: str, public_origin: str) -> str:
    parsed_location = urllib.parse.urlsplit(location)
    if not parsed_location.scheme or not parsed_location.netloc:
        return location

    rewritten_path: Optional[str] = None
    for candidate in proxy_rewrite_candidate_bases(upstream_base):
        upstream = urllib.parse.urlsplit(candidate)
        if (parsed_location.scheme, parsed_location.netloc) != (upstream.scheme, upstream.netloc):
            continue
        upstream_base_path = upstream.path.rstrip("/")
        candidate_path = parsed_location.path or "/"
        if upstream_base_path and candidate_path == upstream_base_path:
            rewritten_path = "/"
            break
        if upstream_base_path and candidate_path.startswith(f"{upstream_base_path}/"):
            rewritten_path = candidate_path[len(upstream_base_path) :] or "/"
            break
        if not upstream_base_path:
            rewritten_path = candidate_path
            break

    if rewritten_path is None:
        return location

    public = urllib.parse.urlsplit(public_origin)
    return urllib.parse.urlunsplit(
        (
            public.scheme,
            public.netloc,
            rewritten_path,
            parsed_location.query,
            parsed_location.fragment,
        )
    )


def cookie_header_names(cookie_header: str) -> list[str]:
    names: list[str] = []
    for item in cookie_header.split(";"):
        name = item.split("=", 1)[0].strip()
        if name:
            names.append(name)
    return names


def summarize_set_cookie_headers(values: list[str]) -> list[str]:
    summarized: list[str] = []
    for value in values:
        parts = [part.strip() for part in value.split(";") if part.strip()]
        if not parts:
            continue
        cookie_name = parts[0].split("=", 1)[0].strip() or "<unknown>"
        attrs = [part.split("=", 1)[0].strip() for part in parts[1:]]
        if attrs:
            summarized.append(f"{cookie_name}; attrs={','.join(attrs)}")
        else:
            summarized.append(cookie_name)
    return summarized


def summarize_request_headers(headers) -> Dict[str, Any]:
    summary: Dict[str, Any] = {}
    for key, value in headers.items():
        lower = key.lower()
        if lower in SENSITIVE_HEADER_NAMES:
            continue
        summary[key] = value
    cookie_value = headers.get("cookie")
    if cookie_value:
        summary["cookie_names"] = cookie_header_names(cookie_value)
    authorization = headers.get("authorization")
    if authorization:
        summary["authorization_scheme"] = authorization.split(" ", 1)[0]
    return summary


def summarize_response_headers(headers: httpx.Headers) -> Dict[str, Any]:
    summary: Dict[str, Any] = {}
    set_cookie_values: list[str] = []
    for key, value in headers.multi_items():
        lower = key.lower()
        if lower == "set-cookie":
            set_cookie_values.append(value)
            continue
        if lower in SENSITIVE_HEADER_NAMES:
            continue
        existing = summary.get(key)
        if existing is None:
            summary[key] = value
        elif isinstance(existing, list):
            existing.append(value)
        else:
            summary[key] = [existing, value]
    if set_cookie_values:
        summary["Set-Cookie"] = summarize_set_cookie_headers(set_cookie_values)
    return summary


def websocket_forward_headers(websocket: WebSocket) -> Dict[str, str]:
    host = websocket.headers.get("host", "")
    port = websocket.url.port
    scheme = websocket.url.scheme
    client_host = websocket.client.host if websocket.client else None
    headers = forwarded_headers(websocket.headers, client_host, scheme, host, port)
    return {key: value for key, value in headers.items() if key.lower() not in WEBSOCKET_STRIP_HEADERS}


app = FastAPI(title="HomeTunnel Add-on")
proxy_app = FastAPI(title="HomeTunnel Home Assistant Proxy")

# The UI/API binds 0.0.0.0 inside a container that also joins the NetBird
# overlay, so without a source check every overlay peer could reach the
# unauthenticated control endpoints. Home Assistant ingress proxies requests
# from the supervisor (172.30.32.2); only that source and loopback are trusted.
UI_TRUSTED_CLIENT_DEFAULTS = ("127.0.0.0/8", "::1/128", "172.30.32.2/32")
_ui_trusted_networks: Optional[list] = None


def ui_trusted_networks() -> list:
    global _ui_trusted_networks
    if _ui_trusted_networks is None:
        entries = list(UI_TRUSTED_CLIENT_DEFAULTS)
        entries.extend(
            item.strip()
            for item in (os.environ.get("UI_TRUSTED_CLIENTS") or "").split(",")
            if item.strip()
        )
        networks = []
        for entry in entries:
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                LOG.warning("Ignoring invalid UI_TRUSTED_CLIENTS entry: %s", entry)
        _ui_trusted_networks = networks
    return _ui_trusted_networks


def ui_client_is_trusted(client_host: Optional[str]) -> bool:
    if not client_host:
        return False
    try:
        address = ipaddress.ip_address(client_host.strip())
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return any(address in network for network in ui_trusted_networks() if address.version == network.version)


@app.middleware("http")
async def enforce_ingress_only_access(request: Request, call_next):
    # /health stays open for the supervisor watchdog.
    if request.url.path == "/health":
        return await call_next(request)
    client_host = request.client.host if request.client else None
    if not ui_client_is_trusted(client_host):
        LOG.warning(
            "Blocked UI request from untrusted client %s: %s %s",
            client_host,
            request.method,
            request.url.path,
        )
        return JSONResponse({"ok": False, "error": "forbidden"}, status_code=403)
    return await call_next(request)
_proxy_stop_event = threading.Event()
_proxy_resolver = HomeAssistantUpstreamResolver(HA_PROXY_CACHE_PATH)
_proxy_http_client: Optional[httpx.AsyncClient] = None


APP_JS = r"""
document.addEventListener("DOMContentLoaded", () => {
  const statusEl = document.getElementById("status");
  const statusAdvancedEl = document.getElementById("statusAdvanced");
  const settingsEl = document.getElementById("settings");
  const authArea = document.getElementById("authArea");
  const pairingNotice = document.getElementById("pairingNotice");
  const pairedArea = document.getElementById("pairedArea");
  const pairedPill = document.getElementById("pairedPill");
  const pairedText = document.getElementById("pairedText");
  const userCode = document.getElementById("userCode");
  const copyCodeBtn = document.getElementById("copyCodeBtn");
  const codeCopyStatus = document.getElementById("codeCopyStatus");
  const authExp = document.getElementById("authExp");
  const pollIntervalEl = document.getElementById("pollInterval");
  const errorBox = document.getElementById("errorBox");
  const startBtn = document.getElementById("startBtn");
  const pollBtn = document.getElementById("pollBtn");
  const resetBtn = document.getElementById("resetBtn");
  const restartAgentBtn = document.getElementById("restartAgentBtn");

  let authError = null;
  let pollTimer = null;
  let refreshTimer = null;
  let currentDeviceCode = "";
  let startInFlight = false;
  const IDLE_REFRESH_MS = 15000;
  const ACTIVE_REFRESH_MS = 3000;

  function isoFromExpiresIn(expiresIn) {
    const seconds = Number(expiresIn);
    if (!Number.isFinite(seconds) || seconds <= 0) return "";
    return new Date(Date.now() + seconds * 1000).toISOString();
  }

  function formatExpiry(expiresAt) {
    if (!expiresAt) return "-";
    const date = new Date(expiresAt);
    if (Number.isNaN(date.getTime())) return String(expiresAt);
    const remainingMs = date.getTime() - Date.now();
    if (remainingMs <= 0) return "Expired";
    const totalSeconds = Math.ceil(remainingMs / 1000);
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = totalSeconds % 60;
    if (minutes > 0) return `${minutes}m ${seconds}s`;
    return `${seconds}s`;
  }

  function formatStatusLabel(value) {
    return String(value || "")
      .replace(/_/g, " ")
      .replace(/\b\w/g, (ch) => ch.toUpperCase())
      .trim();
  }

  function scheduleRefresh(ms) {
    if (refreshTimer) clearTimeout(refreshTimer);
    refreshTimer = window.setTimeout(() => {
      void refresh();
    }, ms);
  }

  function stopPollTimer() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = null;
  }

  function startPollTimer(intervalSeconds) {
    const pollMs = Math.max(3, Number(intervalSeconds || 5)) * 1000;
    stopPollTimer();
    pollTimer = window.setInterval(() => {
      void pollAuth();
    }, pollMs);
  }

  function setPairingNotice(message, busy) {
    pairingNotice.textContent = message || "";
    pairingNotice.classList.toggle("busy", !!busy);
  }

  async function copyTextToClipboard(text) {
    let clipboardError = null;
    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
      try {
        await navigator.clipboard.writeText(text);
        return;
      } catch (error) {
        clipboardError = error;
      }
    }

    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "fixed";
    textarea.style.left = "-9999px";
    textarea.style.top = "0";
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    try {
      if (!document.execCommand("copy")) {
        throw clipboardError || new Error("execCommand copy failed");
      }
    } finally {
      document.body.removeChild(textarea);
    }
  }

  function setUserCode(code) {
    const value = code || "";
    if (userCode.textContent !== value) {
      codeCopyStatus.textContent = "";
    }
    userCode.textContent = value;
    copyCodeBtn.disabled = !value;
  }

  function deriveAuthState(state = {}) {
    const auth = state.device_auth || {};
    const session = state.pairing_session || {};
    return {
      ...auth,
      device_code: session.device_code || auth.device_code || "",
      user_code: session.user_code || auth.user_code || "",
      verification_url: session.verification_url || auth.verification_url || "",
      expires_at: session.pairing_expires_at || auth.expires_at || "",
      poll_interval: session.poll_interval || auth.poll_interval || 5,
      status: session.pairing_status || auth.status || null,
      pairing_inflight: Boolean(session.pairing_inflight),
    };
  }

  function updatePollButton(auth = {}) {
    pollBtn.disabled = !auth.device_code || !!auth.binding_ready || auth.status === "expired" || auth.pairing_inflight;
  }

  function applyAuthState(auth = {}) {
    if (auth.user_code) {
      authArea.style.display = "block";
      setUserCode(auth.user_code);
      authExp.textContent = formatExpiry(auth.expires_at);
      pollIntervalEl.textContent = auth.poll_interval || 5;
    } else {
      authArea.style.display = "none";
      setUserCode("");
      authExp.textContent = "";
      pollIntervalEl.textContent = "5";
    }

    currentDeviceCode = auth.device_code || "";
    updatePollButton(auth);
  }

  function syncPollTimer(auth = {}, view = {}) {
    const shouldPoll = Boolean(auth.device_code) && auth.status !== "expired" && !view.bindingReady;
    if (!shouldPoll) {
      stopPollTimer();
      return;
    }
    startPollTimer(auth.poll_interval || 5);
  }

  function deriveViewState(state = {}) {
    const transportReady = Boolean(state.transport_ready || (state.netbird?.connected && state.netbird?.peer_id));
    const bindingReady = Boolean(
      state.binding_ready || (state.binding?.valid && state.device_id && state.home_id)
    );
    return { transportReady, bindingReady };
  }

  function pairingMessage(state = {}, view = {}, auth = {}) {
    const session = state.pairing_session || {};
    const localStatus = state.local_status || "";
    if (["portal_trust_degraded", "binding_material_missing", "missing_binding_id", "stale_binding", "device_credential_revoked", "peer_id_missing", "peer_mismatch", "re_pair_required", "portal_persistence_failure"].includes(localStatus)) {
      return state.local_status_detail || "A recovery step is required before this device can be trusted again.";
    }
    if (view.transportReady) {
      return "Already connected; reset pairing to pair with a different home.";
    }
    if (view.bindingReady) {
      return "Pairing completed. This device is bound to a home and reconnects automatically.";
    }
    if (session.pairing_inflight || startInFlight) {
      return "Starting pairing…";
    }
    if (auth.status === "expired") {
      return "Pairing code expired. Start pairing to request a new code.";
    }
    if (auth.status === "approved" || auth.status === "already_enrolled") {
      return "Approval received. Completing enrollment…";
    }
    if (auth.device_code) {
      return `Pairing code active (expires in ${formatExpiry(auth.expires_at)}). Waiting for approval.`;
    }
    if (state.pairing_start_blocked_reason === "already_enrolled") {
      return "This device already has enrollment state. Reset pairing to pair with a different home.";
    }
    return "Start pairing to authorize this Home Assistant device.";
  }

  function desiredRefreshMs(state = {}) {
    const session = state.pairing_session || {};
    if (session.pairing_inflight || session.active || session.device_code) {
      return ACTIVE_REFRESH_MS;
    }
    return IDLE_REFRESH_MS;
  }

  function formatError(data) {
    const lines = [];
    if (data.code) lines.push(data.code);
    else if (data.error) lines.push(data.error);
    if (data.upstream_url) lines.push(`Upstream: ${data.upstream_url}`);
    if (data.upstream_status) lines.push(`Status: ${data.upstream_status}`);
    if (data.message) lines.push(data.message);
    return lines.join("\n") || "Request failed";
  }

  function setError(message) {
    if (!message) {
      errorBox.hidden = true;
      errorBox.textContent = "";
      return;
    }
    errorBox.hidden = false;
    errorBox.textContent = message;
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function setDl(el, obj) {
    const rows = Object.entries(obj).map(([k, v]) => `<dt class="muted">${escapeHtml(k)}</dt><dd>${v == null ? "-" : escapeHtml(v)}</dd>`);
    el.innerHTML = rows.join("");
  }

  async function fetchJson(path, options) {
    const res = await fetch(path, options);
    const data = await res.json();
    if (!res.ok || data.ok === false) {
      throw data;
    }
    return data;
  }

  function renderState(data) {
    const s = data.state || {};
    const auth = deriveAuthState(s);
    const session = s.pairing_session || {};
    const view = deriveViewState(s);
    const networkStatus = s.route?.network_status || "waiting";
    startInFlight = Boolean(session.pairing_inflight && !session.device_code);

    const netbirdConnected = s.netbird?.connected;
    setDl(statusEl, {
      "Health": formatStatusLabel(s.route?.health_status) || "-",
      "Binding": formatStatusLabel(s.binding?.status) || "-",
      "NetBird connected": netbirdConnected == null ? "-" : (netbirdConnected ? "Yes" : "No"),
      "Effective target CIDR": s.route?.effective_target_cidr,
    });

    setDl(statusAdvancedEl, {
      auth_status: auth.status,
      pairing_state: s.pairing_state,
      pairing_inflight: session.pairing_inflight,
      pairing_started_at: session.pairing_started_at,
      pairing_expires_at: session.pairing_expires_at,
      pairing_start_allowed: s.pairing_start_allowed,
      pairing_start_blocked_reason: s.pairing_start_blocked_reason,
      paired: s.paired,
      local_status: s.local_status,
      local_status_detail: s.local_status_detail,
      recovery_state: s.recovery_state,
      transport_ready: view.transportReady,
      binding_ready: view.bindingReady,
      access_mode: s.route?.access_mode,
      ha_access_mode: s.route?.ha_access_mode,
      route_mode: s.route?.route_mode,
      routed_endpoint: s.route?.current_endpoint,
      target_hostname: s.route?.effective_target_hostname || s.route?.target_hostname,
      resolved_target_hostname: s.route?.resolved_target_hostname,
      effective_target_hostname: s.route?.effective_target_hostname,
      routed_target_ip: s.route?.target_ip,
      routed_target_source: s.route?.target_source,
      local_tcp_8123_reachable: s.route?.local_tcp_8123_reachable,
      health_status: s.route?.health_status,
      route_needs_report: s.route?.needs_report,
      route_network: s.route?.route_network,
      desired_advertise_routes: s.route?.desired_advertise_routes,
      applied_advertise_routes: s.route?.applied_advertise_routes,
      route_healthy: s.route?.healthy,
      route_last_resolved_at: s.route?.last_resolved_at,
      route_last_reconciled_at: s.route?.last_reconciled_at,
      route_ids: (s.route?.route_ids || []).join(", "),
      policy_ids: (s.route?.policy_ids || []).join(", "),
      peer_group_ids: (s.route?.peer_group_ids || []).join(", "),
      legacy_proxy_url: s.route?.legacy_proxy_url,
      network_status: networkStatus,
      same_lan_detected: s.route?.same_lan_detected,
      exact_ip_conflict: s.route?.exact_ip_conflict,
      subnet_overlap: s.route?.subnet_overlap,
      local_bypass_recommended: s.route?.local_bypass_recommended,
      local_bypass_reason: s.route?.local_bypass_reason,
      effective_target_cidr: s.route?.effective_target_cidr,
      selected_target_ip: s.route?.selected_target_ip,
      resolved_target_ip: s.route?.resolved_target_ip || s.route?.target_ip,
      local_ipv4_addresses: (s.route?.local_ipv4_addresses || []).join(", "),
      local_ipv4_subnets: (s.route?.local_ipv4_subnets || []).join(", "),
      local_ipv4_interfaces: (s.route?.local_ipv4_interfaces || []).map((item) => `${item.interface || "?"}:${item.cidr || "-"}`).join(", "),
      matching_local_subnets: (s.route?.matching_local_subnets || []).join(", "),
      overlay_identity: s.route?.overlay_identity,
      overlay_identity_basis: s.route?.overlay_identity_basis,
      effective_target_identity: s.route?.effective_target_identity,
      netbird_connected: s.netbird?.connected,
      peer_id: s.netbird?.peer_id,
      peer_ip: s.netbird?.peer_ip,
      peer_name: s.netbird?.peer_name || s.peer_name,
      heartbeat_error: s.heartbeat_error,
      binding_status: s.binding?.status,
      binding_valid: s.binding?.valid,
      expected_netbird_label: s.binding?.expected_netbird_label,
      binding_id: s.binding?.binding_id || s.binding?.device_binding_id,
      binding_missing_fields: (s.binding?.missing_fields || []).join(", "),
      netbird_label_apply_status: s.binding?.netbird_label_apply_status,
      device_id: s.device_id,
      home_id: s.home_id,
      management_url: s.management_url,
      ha_proxy_upstream: s.ha_proxy?.selected_url,
      ha_proxy_source: s.ha_proxy?.selected_source,
      ha_proxy_resolved_at: s.ha_proxy?.last_resolved_at,
      ha_proxy_error: s.ha_proxy?.last_error,
      agent_running: s.agent_running,
      last_heartbeat: s.last_heartbeat_at,
      last_health_check_at: s.last_health_check_at,
      last_agent_report_at: s.last_agent_report_at,
      last_health_result: s.last_health_result,
      last_health_report_error: s.last_health_report_error,
      last_error: s.last_error
    });

    setDl(settingsEl, data.options || {});
    applyAuthState({
      ...auth,
      paired: s.paired,
      binding_ready: view.bindingReady,
    });
    syncPollTimer(auth, view);

    startBtn.style.display = "";
    startBtn.disabled = startInFlight || !Boolean(s.pairing_start_allowed);
    startBtn.textContent = startInFlight ? "Starting pairing..." : "Start pairing";
    pollBtn.style.display = auth.device_code && !view.bindingReady ? "" : "none";
    resetBtn.style.display = (view.transportReady || view.bindingReady || s.paired || auth.device_code || session.pairing_inflight) ? "" : "none";
    setPairingNotice(pairingMessage(s, view, auth), startInFlight);

    if (authError) {
      authArea.style.display = "block";
      setUserCode(authError.code || authError.error || "auth_error");
      authExp.textContent = authError.upstream_status || authError.message || "-";
      pollIntervalEl.textContent = "-";
      currentDeviceCode = auth.device_code || "";
      updatePollButton({
        ...auth,
        paired: s.paired,
        binding_ready: view.bindingReady,
      });
    }

    const trustDegraded = s.local_status === "portal_trust_degraded";
    const recoveryVisible = ["portal_trust_degraded", "binding_material_missing", "missing_binding_id", "stale_binding", "device_credential_revoked", "peer_id_missing", "peer_mismatch", "re_pair_required", "portal_persistence_failure"].includes(s.local_status || "");
    if (trustDegraded) {
      pairedArea.style.display = "block";
      pairedPill.textContent = "Portal trust degraded";
      pairedText.textContent = s.local_status_detail || "Tunnel transport is connected, but the portal heartbeat trust check failed.";
    } else if (view.bindingReady) {
      pairedArea.style.display = "block";
      pairedPill.textContent = "Paired to home";
      pairedText.textContent = "Enrollment is complete. This add-on will keep NetBird connected automatically.";
    } else if (view.transportReady) {
      pairedArea.style.display = "block";
      if (networkStatus === "exact_ip_conflict") {
        pairedPill.textContent = "IP conflict detected";
        pairedText.textContent = "The resolved target matches a local IPv4 address. Use the tunnel path until the home network changes.";
      } else if (networkStatus === "same_lan") {
        pairedPill.textContent = "Using local connection";
        pairedText.textContent = "The target appears on the same LAN. Local bypass is recommended and this is not an error.";
      } else if (networkStatus === "subnet_overlap") {
        pairedPill.textContent = "Subnet overlap detected";
        pairedText.textContent = "The target IP falls within a local subnet. Direct host-only routing should stay exact and not widen to a subnet route.";
      } else if (networkStatus === "waiting") {
        pairedPill.textContent = "Waiting for network information";
        pairedText.textContent = "Route and local network details are still being collected.";
      } else {
        pairedPill.textContent = "Tunnel transport connected";
        pairedText.textContent = "NetBird transport is ready. Portal trust is reported separately.";
      }
    } else if (recoveryVisible) {
      pairedArea.style.display = "block";
      pairedPill.textContent = formatStatusLabel(s.local_status || "recovery_required");
      pairedText.textContent = s.local_status_detail || "A recovery step is required before this device can be trusted again.";
    } else {
      pairedArea.style.display = "none";
    }

    scheduleRefresh(desiredRefreshMs(s));
  }

  async function refresh() {
    try {
      const data = await fetchJson("./api/status");
      renderState(data);
      if (!authError) {
        setError("");
      }
    } catch (error) {
      console.error("[HomeTunnel UI] status refresh failed", error);
      setError(`Status refresh failed: ${formatError(error)}`);
      scheduleRefresh(ACTIVE_REFRESH_MS);
    }
  }

  async function startAuth() {
    try {
      startInFlight = true;
      authError = null;
      setError("");
      setPairingNotice("Starting pairing…", true);
      startBtn.disabled = true;
      startBtn.textContent = "Starting pairing...";
      const data = await fetchJson("./api/auth/start", { method: "POST" });
      const expiresAt = data.expires_at || isoFromExpiresIn(data.expires_in);
      const nextAuth = {
        device_code: data.device_code || "",
        user_code: data.user_code || "",
        verification_url: data.verification_url || "",
        expires_at: expiresAt,
        poll_interval: data.interval || 5,
        status: data.status || "starting",
        pairing_inflight: Boolean(data.pairing_inflight),
        paired: false,
      };
      applyAuthState(nextAuth);
      startInFlight = Boolean(data.pairing_inflight && !data.device_code);
      syncPollTimer(nextAuth, { transportReady: false, bindingReady: false });
      scheduleRefresh(400);
      window.setTimeout(() => { void refresh(); }, 1200);
      window.setTimeout(() => { void refresh(); }, 2500);
    } catch (error) {
      startInFlight = false;
      authError = error;
      console.error("[HomeTunnel UI] auth start failed", error);
      setError(`Pairing start failed: ${formatError(error)}`);
      await refresh();
    }
  }

  async function pollAuth() {
    if (!currentDeviceCode) {
      setError("Start device authorization before checking approval.");
      return;
    }

    try {
      const data = await fetchJson("./api/auth/poll", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ device_code: currentDeviceCode }),
      });
      authError = null;
      setError("");
      if (data.status === "pending" || data.code === "not_approved") {
        await refresh();
        return;
      }
      if (data.paired || data.status === "expired") {
        stopPollTimer();
      }
      await refresh();
    } catch (error) {
      authError = error;
      console.error("[HomeTunnel UI] auth poll failed", error);
      setError(`Approval check failed: ${formatError(error)}`);
      await refresh();
    }
  }

  async function ping() {
    try {
      await fetchJson("./api/ping");
    } catch (error) {
      setError(`UI connectivity check failed: ${formatError(error)}`);
    }
  }

  async function restartAgent() {
    try {
      restartAgentBtn.disabled = true;
      await fetchJson("./api/agent/restart", { method: "POST" });
      setError("");
      await refresh();
    } catch (error) {
      setError(`Agent restart failed: ${formatError(error)}`);
    } finally {
      restartAgentBtn.disabled = false;
    }
  }

  async function resetPairing() {
    try {
      resetBtn.disabled = true;
      const data = await fetchJson("./api/pairing/reset", { method: "POST" });
      const portalCleanupError = data.portal_cleanup?.error;
      if (portalCleanupError && data.portal_cleanup?.attempted !== false) {
        setError(`Local reset completed, but portal cleanup failed: ${portalCleanupError}`);
      } else if (portalCleanupError) {
        setError(`Local reset completed. Portal cleanup is still required: ${portalCleanupError}`);
      } else {
        setError("");
      }
      authError = null;
      startInFlight = false;
      currentDeviceCode = "";
      stopPollTimer();
      await refresh();
    } catch (error) {
      setError(`Reset pairing failed: ${formatError(error)}`);
    } finally {
      resetBtn.disabled = false;
    }
  }

  copyCodeBtn.addEventListener("click", async () => {
    const code = userCode.textContent || "";
    if (!code) return;
    try {
      await copyTextToClipboard(code);
      codeCopyStatus.textContent = "Copied";
    } catch (error) {
      codeCopyStatus.textContent = "Copy failed — copy the code manually";
    }
  });

  startBtn.addEventListener("click", () => {
    console.log("[HomeTunnel UI] click Start pairing");
    void startAuth();
  });
  pollBtn.addEventListener("click", pollAuth);
  resetBtn.addEventListener("click", () => {
    void resetPairing();
  });
  restartAgentBtn.addEventListener("click", () => {
    void restartAgent();
  });

  void ping();
  void refresh();
});
"""


@app.on_event("startup")
def startup_event() -> None:
    install_uvicorn_log_redaction()
    load_state()
    persist_runtime_observations(load_options())
    start_netbird_agent_if_needed()
    thread = threading.Thread(target=ui_refresh_loop, daemon=True)
    thread.start()
    print(f"UI listening on http://{LISTEN_HOST}:{LISTEN_PORT}", flush=True)


@app.on_event("shutdown")
def shutdown_event() -> None:
    _stop_event.set()


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"ok": True}


@app.get("/api/ping")
def api_ping() -> Dict[str, Any]:
    LOG.info("GET /api/ping")
    return {"ok": True, "message": "pong"}


@app.get("/api/status")
def api_status() -> Dict[str, Any]:
    LOG.info("GET /api/status")
    global _options
    _options = load_options()
    state_copy = redact_state(refresh_runtime_state())
    return {
        "ok": True,
        "options": _options,
        "state": state_copy,
        "netbird_agent_running": bool(state_copy.get("agent_running")),
    }


@app.get("/api/binding/status")
def api_binding_status() -> Dict[str, Any]:
    LOG.info("GET /api/binding/status")
    state_copy = redact_state(refresh_runtime_state())
    binding = dict(state_copy.get("binding") or {})
    return {
        "ok": True,
        "binding": binding,
        "transport_ready": bool(state_copy.get("transport_ready")),
        "binding_ready": bool(state_copy.get("binding_ready")),
        "peer_id": (state_copy.get("netbird") or {}).get("peer_id"),
        "peer_ip": (state_copy.get("netbird") or {}).get("peer_ip"),
        "peer_name": (state_copy.get("netbird") or {}).get("peer_name") or state_copy.get("peer_name"),
        "device_id": state_copy.get("device_id"),
        "home_id": state_copy.get("home_id"),
        "last_heartbeat": state_copy.get("last_heartbeat_at"),
        "last_health_check_at": state_copy.get("last_health_check_at"),
        "last_agent_report_at": state_copy.get("last_agent_report_at"),
        "last_health_result": state_copy.get("last_health_result"),
        "last_health_report_error": state_copy.get("last_health_report_error"),
    }


@app.get("/api/route/status")
def api_route_status() -> Dict[str, Any]:
    LOG.info("GET /api/route/status")
    global _options
    _options = load_options()
    state_copy = redact_state(refresh_runtime_state())
    route_state = dict(state_copy.get("route") or {})
    return {
        "ok": True,
        "transport_ready": bool(state_copy.get("transport_ready")),
        "binding_ready": bool(state_copy.get("binding_ready")),
        "access_mode": route_state.get("access_mode"),
        "ha_access_mode": route_state.get("ha_access_mode"),
        "route_mode": route_state.get("route_mode"),
        "current_endpoint": route_state.get("current_endpoint"),
        "legacy_proxy_url": route_state.get("legacy_proxy_url"),
        "peer_id": (state_copy.get("netbird") or {}).get("peer_id"),
        "peer_ip": (state_copy.get("netbird") or {}).get("peer_ip"),
        "peer_name": (state_copy.get("netbird") or {}).get("peer_name") or state_copy.get("peer_name"),
        "target_host": route_state.get("target_host"),
        "target_hostname": route_state.get("target_hostname"),
        "resolved_target_hostname": route_state.get("resolved_target_hostname") or route_state.get("target_hostname"),
        "effective_target_hostname": route_state.get("effective_target_hostname"),
        "overlay_identity": route_state.get("overlay_identity"),
        "selected_target_ip": route_state.get("selected_target_ip"),
        "target_ip": route_state.get("target_ip"),
        "resolved_target_ip": route_state.get("resolved_target_ip") or route_state.get("target_ip"),
        "target_port": route_state.get("target_port"),
        "target_source": route_state.get("target_source"),
        "target_reachable": route_state.get("target_reachable"),
        "local_tcp_8123_reachable": route_state.get("local_tcp_8123_reachable"),
        "health_status": route_state.get("health_status"),
        "route_network": route_state.get("route_network"),
        "desired_advertise_routes": route_state.get("desired_advertise_routes"),
        "applied_advertise_routes": route_state.get("applied_advertise_routes"),
        "effective_target_cidr": route_state.get("effective_target_cidr"),
        "local_ipv4_addresses": route_state.get("local_ipv4_addresses") or [],
        "local_ipv4_subnets": route_state.get("local_ipv4_subnets") or [],
        "local_ipv4_interfaces": route_state.get("local_ipv4_interfaces") or [],
        "matching_local_subnets": route_state.get("matching_local_subnets") or [],
        "same_lan_detected": route_state.get("same_lan_detected"),
        "exact_ip_conflict": route_state.get("exact_ip_conflict"),
        "subnet_overlap": route_state.get("subnet_overlap"),
        "local_bypass_recommended": route_state.get("local_bypass_recommended"),
        "local_bypass_reason": route_state.get("local_bypass_reason"),
        "network_status": route_state.get("network_status"),
        "overlay_identity": route_state.get("overlay_identity"),
        "hometunnel_dns_hostname": route_state.get("hometunnel_dns_hostname"),
        "hometunnel_display_identity": route_state.get("hometunnel_display_identity"),
        "overlay_identity_basis": route_state.get("overlay_identity_basis"),
        "effective_target_identity": route_state.get("effective_target_identity"),
        "last_resolved_at": route_state.get("last_resolved_at"),
        "last_reconciled_at": route_state.get("last_reconciled_at"),
        "needs_report": route_state.get("needs_report"),
        "route_ids": route_state.get("route_ids") or [],
        "peer_group_ids": route_state.get("peer_group_ids") or [],
        "policy_ids": route_state.get("policy_ids") or [],
        "healthy": route_state.get("healthy"),
        "last_error": route_state.get("last_error"),
        "last_health_check_at": state_copy.get("last_health_check_at"),
        "last_agent_report_at": state_copy.get("last_agent_report_at"),
        "last_health_result": state_copy.get("last_health_result"),
        "last_health_report_error": state_copy.get("last_health_report_error"),
        "binding_status": (state_copy.get("binding") or {}).get("status"),
        "expected_netbird_label": (state_copy.get("binding") or {}).get("expected_netbird_label"),
        "network": {
            "local_ipv4_addresses": route_state.get("local_ipv4_addresses") or [],
            "local_ipv4_subnets": route_state.get("local_ipv4_subnets") or [],
            "local_ipv4_interfaces": route_state.get("local_ipv4_interfaces") or [],
            "local_ipv4_source": route_state.get("local_ipv4_source"),
            "local_ipv4_error": route_state.get("local_ipv4_error"),
            "matching_local_subnets": route_state.get("matching_local_subnets") or [],
            "same_lan_detected": route_state.get("same_lan_detected"),
            "exact_ip_conflict": route_state.get("exact_ip_conflict"),
            "subnet_overlap": route_state.get("subnet_overlap"),
            "local_bypass_recommended": route_state.get("local_bypass_recommended"),
            "local_bypass_reason": route_state.get("local_bypass_reason"),
            "network_status": route_state.get("network_status"),
            "overlay_identity": route_state.get("overlay_identity"),
            "hometunnel_dns_hostname": route_state.get("hometunnel_dns_hostname"),
            "hometunnel_display_identity": route_state.get("hometunnel_display_identity"),
            "overlay_identity_basis": route_state.get("overlay_identity_basis"),
            "effective_target_identity": route_state.get("effective_target_identity"),
            "effective_target_cidr": route_state.get("effective_target_cidr"),
        },
    }


@app.get("/api/heartbeat/diagnostics")
def api_heartbeat_diagnostics() -> Dict[str, Any]:
    LOG.info("GET /api/heartbeat/diagnostics")
    options = load_options()
    state_snapshot = read_state_snapshot()
    diagnostics = heartbeat_transport_diagnostics(state_snapshot, options)
    LOG.info(
        "heartbeat diagnostics intended_host=%s phase=%s last_destination=%s nameservers=%s",
        diagnostics.get("intended_heartbeat_host") or "<unknown>",
        diagnostics.get("netbird_dns_phase"),
        diagnostics.get("last_heartbeat_destination") or "<none>",
        ",".join(diagnostics.get("resolver", {}).get("nameservers") or []) or "<none>",
    )
    return {"ok": True, "diagnostics": diagnostics}


@app.post("/api/auth/start")
def api_auth_start() -> JSONResponse:
    LOG.info("POST /api/auth/start")
    global _options
    _options = load_options()
    state_snapshot = refresh_runtime_state()
    pairing_session = normalize_pairing_session_state(state_snapshot)
    if pairing_session.get("pairing_status") == "expired":
        update_state(lambda state: clear_pairing_session_state(state))
        state_snapshot = refresh_runtime_state()
        pairing_session = normalize_pairing_session_state(state_snapshot)
    if pairing_session_is_reusable(pairing_session):
        state_snapshot = status_view_from_state(read_state_snapshot(), _options)
        return JSONResponse(pairing_session_response_payload(state_snapshot, reused=True))
    start_allowed, blocked_reason = pairing_start_gate(state_snapshot, pairing_session)
    if not start_allowed:
        if blocked_reason == "pairing_inflight":
            return JSONResponse(pairing_session_response_payload(state_snapshot))
        message = "Pairing is already starting." if blocked_reason == "pairing_inflight" else (
            "Already connected; reset pairing to pair with a different home." if blocked_reason == "transport_ready" else (
                "An active pairing code already exists. Reuse the current code until it expires or reset pairing." if blocked_reason == "active_pairing_session" else
                "Reset pairing before starting a new device authorization flow."
            )
        )
        return JSONResponse(
            {
                "ok": False,
                "code": blocked_reason or "pairing_blocked",
                "message": message,
            },
            status_code=409 if blocked_reason in {"transport_ready", "already_enrolled", "active_pairing_session"} else 429,
        )
    local_device_id = ensure_local_device_id()
    started_at = now_iso()
    with _pairing_start_lock:
        latest_state = status_view_from_state(read_state_snapshot(), _options)
        latest_session = normalize_pairing_session_state(latest_state)
        if latest_session.get("pairing_status") == "expired":
            update_state(lambda state: clear_pairing_session_state(state))
            latest_state = status_view_from_state(read_state_snapshot(), _options)
            latest_session = normalize_pairing_session_state(latest_state)
        if pairing_session_is_reusable(latest_session):
            return JSONResponse(pairing_session_response_payload(latest_state, reused=True))
        start_allowed, blocked_reason = pairing_start_gate(latest_state, latest_session)
        if not start_allowed:
            if blocked_reason == "pairing_inflight":
                return JSONResponse(pairing_session_response_payload(latest_state))
            return JSONResponse(
                {
                    "ok": False,
                    "code": blocked_reason or "pairing_blocked",
                    "message": "Pairing start is currently blocked.",
                },
                status_code=409 if blocked_reason in {"transport_ready", "already_enrolled", "active_pairing_session"} else 429,
            )

        def mutate(state: Dict[str, Any]) -> None:
            state["local_device_id"] = local_device_id
            update_pairing_session_state(
                state,
                {
                    "device_code": None,
                    "user_code": None,
                    "verification_url": None,
                    "pairing_started_at": started_at,
                    "pairing_expires_at": pairing_deadline_iso(started_at),
                    "pairing_status": "starting",
                    "pairing_inflight": True,
                    "poll_interval": 5,
                },
                replace=True,
            )
            state["device_auth"]["enroll_attempted"] = False
            state["device_auth"]["enroll_attempted_at"] = None
            state["device_auth"]["next_enroll_after"] = None
            state["last_pair_check"] = None
            state["last_error"] = None

        update_state(mutate)
        thread = threading.Thread(target=run_pairing_start_request, args=(local_device_id, started_at), daemon=True)
        thread.start()

    return JSONResponse(pairing_session_response_payload(refresh_runtime_state()))


@app.post("/api/auth/poll")
async def api_auth_poll(request: Request) -> JSONResponse:
    LOG.info("POST /api/auth/poll")
    global _options
    _options = load_options()
    request_data: Dict[str, Any] = {}
    try:
        request_data = await request.json()
    except Exception:
        request_data = {}
    state_snapshot = refresh_runtime_state()
    pairing_session = normalize_pairing_session_state(state_snapshot)
    device_auth = dict(state_snapshot.get("device_auth") or {})
    local_device_id = str(state_snapshot.get("local_device_id") or ensure_local_device_id())

    if pairing_session_is_expired(pairing_session):
        update_state(lambda state: update_pairing_session_state(state, {"pairing_status": "expired", "pairing_inflight": False}))
        return JSONResponse({"ok": True, "status": "expired"})

    device_code = request_data.get("device_code") or pairing_session.get("device_code") or device_auth.get("device_code")
    if not device_code:
        return JSONResponse(
            {
                "ok": False,
                "code": "no_active_device_auth",
                "message": "Start device authorization before polling.",
            },
            status_code=400,
        )

    if device_code != pairing_session.get("device_code"):
        update_state(lambda state: update_pairing_session_state(state, {"device_code": device_code}))

    auth_poll_path = f"/api/agent/device-auth/status?device_code={urllib.parse.quote(str(device_code))}"
    try:
        auth_result, status_url, _resolved_base = portal_request_json(
            "GET",
            auth_poll_path,
            state=state_snapshot,
            options=_options,
            purpose="device auth poll",
        )
    except urllib.error.HTTPError as exc:
        status_url = getattr(exc, "_hometunnel_url", f"{_options['hometunnel_url']}{auth_poll_path}")
        if exc.code in (404, 410):
            update_state(lambda state: update_pairing_session_state(state, {"pairing_status": "expired", "pairing_inflight": False}))
            return JSONResponse({"ok": True, "status": "expired"})
        return map_upstream_error("device_auth_status", status_url, exc)
    except Exception as exc:
        status_url = getattr(exc, "_hometunnel_url", f"{_options['hometunnel_url']}{auth_poll_path}")
        return connectivity_error_response(status_url, exc)
    LOG.warning(
        "upstream request path=%s status=%s body=%s",
        upstream_path(status_url),
        200,
        safe_body_preview(json.dumps(auth_result)),
    )

    auth_status = str(first_present(auth_result, "status", "auth_status") or "pending")
    approved = is_auth_approved(auth_status)
    enroll_ready = approved or has_onboarding_payload(auth_result)
    effective_status = "approved" if enroll_ready else auth_status
    update_state(lambda state: state.update({"last_pair_check": now_iso(), "last_error": None}))
    update_state(lambda state: update_pairing_session_state(state, {"pairing_status": effective_status, "pairing_inflight": False}))

    if not enroll_ready:
        return JSONResponse({"ok": True, "status": effective_status})

    with _state_lock:
        if _state.get("paired") and binding_ready_from_state(dict(_state)):
            return JSONResponse(
                {
                    "ok": True,
                    "status": "approved",
                    "paired": True,
                    "deviceId": _state.get("device_id"),
                    "homeId": _state.get("home_id"),
                    "peerName": _state.get("peer_name"),
                }
            )
        device_auth = _state.get("device_auth") or {}
        next_enroll_after = device_auth.get("next_enroll_after")

    if next_enroll_after:
        try:
            if datetime.fromisoformat(str(next_enroll_after)) > datetime.now(timezone.utc):
                return JSONResponse({"ok": True, "status": effective_status})
        except Exception:
            pass

    update_state(
        lambda state: state["device_auth"].update(
            {
                "enroll_attempted": True,
                "enroll_attempted_at": now_iso(),
                "next_enroll_after": None,
            }
        )
    )

    state_snapshot = read_state_snapshot()
    enroll_path = "/api/agent/enroll"
    health_check_interval_seconds = max(1, int(HEALTH_REPORT_INTERVAL_SECONDS))
    enroll_payload = {
        "device_code": device_code,
        "local_device_id": local_device_id,
        "health_check_interval_seconds": health_check_interval_seconds,
    }
    try:
        enroll_result, enroll_url, resolved_portal_base = portal_request_json(
            "POST",
            enroll_path,
            state=state_snapshot,
            options=_options,
            payload=enroll_payload,
            purpose="device enroll",
        )
    except urllib.error.HTTPError as exc:
        enroll_url = getattr(exc, "_hometunnel_url", f"{_options['hometunnel_url']}{enroll_path}")
        body = read_http_error_body(exc)
        log_upstream_result(enroll_url, exc.code, body)
        if exc.code == 409:
            try:
                error_payload = json.loads(body) if body else {}
            except Exception:
                error_payload = {}
            if str(error_payload.get("code") or "").lower() == "not_approved":
                update_state(lambda state: state["device_auth"].update({"enroll_attempted": False, "next_enroll_after": None}))
                return JSONResponse({"ok": True, "status": "approved"})
        if exc.code in (404, 410):
            update_state(
                lambda state: (
                    clear_pairing_session_state(state),
                    state.update({"last_error": f"enroll_http_{exc.code}", "recovery_state": None}),
                )
            )
            return enroll_http_error_response(enroll_url, exc.code, body)
        if exc.code in (400, 401, 403):
            update_state(
                lambda state: (
                    state.update({"last_error": f"enroll_http_{exc.code}", "recovery_state": "re_pair_required"}),
                    state["device_auth"].update({"enroll_attempted": False, "next_enroll_after": None}),
                )
            )
            return enroll_http_error_response(enroll_url, exc.code, body)
        update_state(
            lambda state: (
                state.update(
                    {
                        "last_error": f"enroll_http_{exc.code}",
                    }
                ),
                state["device_auth"].update({"enroll_attempted": False, "next_enroll_after": enroll_retry_after_iso(state["device_auth"])}),
            )
        )
        return enroll_http_error_response(enroll_url, exc.code, body)
    except Exception as exc:
        enroll_url = getattr(exc, "_hometunnel_url", f"{_options['hometunnel_url']}{enroll_path}")
        safe_error = sanitize_error_text(exc, secret_source=state_snapshot)
        update_state(
            lambda state: (
                state.update(
                    {
                        "last_error": f"enroll_error:{safe_error}",
                    }
                ),
                state["device_auth"].update({"enroll_attempted": False, "next_enroll_after": enroll_retry_after_iso(state["device_auth"])}),
            )
        )
        return connectivity_error_response(enroll_url, exc)

    enroll_status = str(first_present(enroll_result, "status") or "")
    enrollment_fields = merge_enrollment_fields(state_snapshot, extract_enrollment_fields(enroll_result))
    enrollment_recoverable = has_recoverable_enrollment_fields(enrollment_fields)

    if enroll_status.lower() == "already_enrolled":
        if not enrollment_recoverable:
            missing_message = (
                "remote enrollment already exists but local enrollment state is missing; "
                "generate a new pairing code"
            )

            def mark_missing_local_enrollment(state: Dict[str, Any]) -> None:
                state["paired"] = False
                state["device_id"] = None
                state["home_id"] = None
                state["binding"] = default_binding_state()
                state["peer_name"] = None
                state["management_url"] = None
                state["setup_key"] = None
                state["device_token"] = None
                state["netbird_peer_id"] = None
                state["labels"] = []
                state["agent_running"] = False
                state["last_health_check_at"] = None
                state["last_agent_report_at"] = None
                state["last_health_result"] = None
                state["last_health_report_error"] = None
                state["recovery_state"] = "re_pair_required"
                update_pairing_session_state(state, {"pairing_status": "already_enrolled_missing_local_state", "pairing_inflight": False})
                state["last_error"] = missing_message

            update_state(mark_missing_local_enrollment)
            return JSONResponse(
                {
                    "ok": False,
                    "code": "already_enrolled_missing_local_state",
                    "status": "already_enrolled",
                    "message": missing_message,
                },
                status_code=409,
            )

    device_id = enrollment_fields["device_id"]
    home_id = enrollment_fields["home_id"]
    device_token = enrollment_fields["device_token"]
    labels = enrollment_fields["labels"]
    management_url = enrollment_fields["management_url"]
    peer_name = enrollment_fields["peer_name"]
    setup_key = enrollment_fields["setup_key"]
    netbird_peer_id = enrollment_fields.get("netbird_peer_id")
    incoming_binding = normalize_binding_state(
        {
            **state_snapshot,
            "device_id": device_id,
            "home_id": home_id,
            "labels": labels,
            "binding": {
                **merge_binding_sources({}, enrollment_fields.get("binding"), clear_portal_validation=True),
                "received_at": now_iso(),
            },
        }
    )
    previous_binding = normalize_binding_state(state_snapshot)
    rotated_fields = binding_rotation_fields(previous_binding, incoming_binding)

    LOG.info(
        "binding received device_id=%s home_id=%s status=%s expected_label=%s missing_fields=%s has_signed_token=%s setup_key_id=%s",
        device_id,
        home_id,
        incoming_binding.get("status"),
        incoming_binding.get("expected_netbird_label") or "<missing>",
        ",".join(incoming_binding.get("missing_fields") or []) or "<none>",
        bool(incoming_binding.get("signed_binding_token")),
        incoming_binding.get("setup_key_id") or "<none>",
    )
    if rotated_fields and previous_binding.get("status") != "missing":
        LOG.info(
            "binding rotation/replacement device_id=%s home_id=%s changed_fields=%s previous_binding_id=%s next_binding_id=%s",
            device_id,
            home_id,
            ",".join(rotated_fields),
            log_secret_marker(previous_binding.get("binding_id") or previous_binding.get("device_binding_id"), missing="<none>"),
            log_secret_marker(incoming_binding.get("binding_id") or incoming_binding.get("device_binding_id"), missing="<none>"),
        )
    if incoming_binding.get("status") in {"missing", "invalid"}:
        LOG.warning(
            "missing binding device_id=%s home_id=%s status=%s validation_error=%s missing_fields=%s",
            device_id,
            home_id,
            incoming_binding.get("status"),
            incoming_binding.get("validation_error") or "<none>",
            ",".join(incoming_binding.get("missing_fields") or []) or "<none>",
        )
    if incoming_binding.get("validation_error") in {"binding_device_id_mismatch", "binding_home_id_mismatch"}:
        LOG.warning(
            "mixed identity detected true device_id=%s home_id=%s validation_error=%s incoming_binding_device_id=%s incoming_binding_home_id=%s",
            device_id,
            home_id,
            incoming_binding.get("validation_error"),
            incoming_binding.get("device_id") or "<missing>",
            incoming_binding.get("home_id") or "<missing>",
        )

        def reject_mixed_identity(state: Dict[str, Any]) -> None:
            clear_local_identity_state(state, reset_route=True)
            state["recovery_state"] = "re_pair_required"
            state["last_error"] = "mixed_identity_state"

        update_state(reject_mixed_identity)
        return JSONResponse(
            {
                "ok": False,
                "code": "mixed_identity_state",
                "message": "Pairing response mixed home/device/binding identity. Reset pairing and pair again.",
            },
            status_code=409,
        )
    LOG.info("mixed identity detected false device_id=%s home_id=%s", device_id, home_id)

    if not enrollment_recoverable:
        update_state(
            lambda state: (
                state.update(
                    {
                        "last_error": "enroll_invalid_response",
                    }
                ),
                state["device_auth"].update(
                    {
                        "enroll_attempted": False,
                        "enroll_attempted_at": None,
                        "next_enroll_after": None,
                    }
                ),
            )
        )
        log_upstream_result(enroll_url, 200, json.dumps(enroll_result))
        return JSONResponse(
            {
                "ok": False,
                "code": "enroll_invalid_response",
                "upstream_url": upstream_path(enroll_url),
                "upstream_status": 200,
                "message": "Upstream enrollment response missing required fields.",
            },
            status_code=424,
        )

    def mutate(state: Dict[str, Any]) -> None:
        binding_state = normalize_binding_state(
            {
                **state,
                "device_id": device_id,
                "home_id": home_id,
                "labels": labels,
                "binding": {
                    **merge_binding_sources({}, enrollment_fields.get("binding"), clear_portal_validation=True),
                    "received_at": incoming_binding.get("received_at"),
                    "persisted_at": now_iso(),
                },
            }
        )
        if rotated_fields:
            binding_state["rotation_count"] = int(previous_binding.get("rotation_count") or 0) + 1
        state["paired"] = True
        state["labels"] = labels
        state["device_id"] = device_id
        state["home_id"] = home_id
        state["binding"] = binding_state
        state["peer_name"] = peer_name or build_device_name()
        state["management_url"] = management_url
        state["setup_key"] = setup_key
        state["device_token"] = device_token
        state["netbird_peer_id"] = netbird_peer_id
        state["agent_running"] = is_netbird_agent_running()
        state["last_health_check_at"] = None
        state["last_agent_report_at"] = None
        state["last_health_result"] = None
        state["last_health_report_error"] = None
        state["last_error"] = None
        state["device_auth"].update({"enroll_attempted": False, "enroll_attempted_at": None, "next_enroll_after": None})

    update_state(mutate)
    LOG.info(
        "new pairing stored home_id=%s device_id=%s binding_id=%s status=%s expected_label=%s portal_base_url=%s",
        home_id,
        device_id,
        log_secret_marker(incoming_binding.get("binding_id") or incoming_binding.get("device_binding_id")),
        incoming_binding.get("status"),
        incoming_binding.get("expected_netbird_label") or "<missing>",
        resolved_portal_base or state_snapshot.get("portal_base_url") or "<unchanged>",
    )

    warning = None
    if is_private_management_url(str(management_url)):
        warning = "management_url_not_public_todo"
        update_state(lambda state: state.update({"last_error": warning}))
    else:
        start_netbird_agent_if_needed()

    return JSONResponse(
        {
            "ok": True,
            "status": "approved" if enroll_status.lower() != "already_enrolled" else "already_enrolled",
            "paired": True,
            "deviceId": device_id,
            "homeId": home_id,
            "peerName": peer_name or build_device_name(),
            "managementUrl": management_url,
            "bindingStatus": incoming_binding.get("status"),
            "expectedNetbirdLabel": incoming_binding.get("expected_netbird_label"),
            "warning": warning,
        }
    )


@app.post("/api/pairing/reset")
def api_pairing_reset() -> JSONResponse:
    LOG.info("POST /api/pairing/reset")
    invalidate_runtime_caches("pairing_reset")
    state_snapshot = read_state_snapshot()
    LOG.info(
        "pairing reset started home_id_present=%s device_id_present=%s binding_id_present=%s token_present=%s setup_key_present=%s",
        bool(normalize_optional_string(state_snapshot.get("home_id"))),
        bool(normalize_optional_string(state_snapshot.get("device_id"))),
        bool(safe_binding_identifier(normalize_binding_state(state_snapshot))),
        bool(normalize_optional_string(state_snapshot.get("device_token"))),
        bool(normalize_optional_string(state_snapshot.get("setup_key"))),
    )
    netbird_down = {"attempted": False, "ok": False, "error": None}
    if netbird_binary_path():
        netbird_down["attempted"] = True
        rc, out, err = run_command(netbird_command("down"), timeout_seconds=20)
        netbird_down["ok"] = rc == 0
        if rc != 0:
            netbird_down["error"] = sanitize_error_text((err or out or "netbird_down_failed").strip(), secret_source=state_snapshot)
    stop_agent_supervisor()
    stop_netbird_daemon()
    delete_path_if_exists(NETBIRD_CONFIG_PATH)
    delete_path_if_exists(NETBIRD_SOCKET_PATH)
    portal_cleanup = portal_reset_cleanup_result(state_snapshot)

    def mutate(state: Dict[str, Any]) -> None:
        clear_local_identity_state(state, reset_route=True)
        state["portal_reset_cleanup_result"] = portal_cleanup

    update_state(mutate)
    return JSONResponse(
        {
            "ok": True,
            "reset": True,
            "netbird_down": netbird_down,
            "portal_cleanup": portal_cleanup,
        }
    )


@app.post("/api/agent/restart")
def api_agent_restart() -> JSONResponse:
    LOG.info("POST /api/agent/restart")
    invalidate_runtime_caches("api_agent_restart")
    state = refresh_runtime_state()
    if not netbird_binary_path():
        update_last_error("netbird binary not found")
        return JSONResponse(
            {"ok": False, "code": "netbird_binary_missing", "message": "NetBird binary is not installed."},
            status_code=500,
        )
    missing_reason = missing_enrollment_reason(state)
    if missing_reason:
        update_last_error(missing_reason)
        return JSONResponse(
            {"ok": False, "code": "missing_enrollment_state", "message": missing_reason},
            status_code=409,
        )
    if is_private_management_url(str(state.get("management_url") or "")):
        update_last_error("management_url_not_public_todo")
        return JSONResponse(
            {
                "ok": False,
                "code": "management_url_not_public",
                "message": "Returned management_url is not client reachable.",
            },
            status_code=424,
        )

    with exclusive_file_lock(NETBIRD_AGENT_START_LOCK_PATH):
        stop_agent_supervisor()
        stop_netbird_daemon()
        started = start_netbird_agent_if_needed_locked()
    if not started:
        state = refresh_runtime_state()
        return JSONResponse(
            {
                "ok": False,
                "code": "agent_restart_failed",
                "message": state.get("last_error") or "failed to start agent",
            },
            status_code=500,
        )
    if not wait_for_agent_running():
        state = refresh_runtime_state()
        return JSONResponse(
            {
                "ok": False,
                "code": "agent_not_running",
                "message": state.get("last_error") or "agent did not stay running",
            },
            status_code=500,
        )
    return JSONResponse({"ok": True, "started": True})


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>HomeTunnel Add-on</title>
    <style>
      :root {
        color-scheme: light;
        --bg: #f3f6f4;
        --card: #ffffff;
        --line: #d9e2dc;
        --ink: #10211a;
        --muted: #4f6358;
        --accent: #123524;
        --accent-alt: #2f6b49;
      }
      body {
        margin: 0;
        font-family: "Avenir Next", "Segoe UI", sans-serif;
        background:
          radial-gradient(circle at top right, rgba(47, 107, 73, 0.12), transparent 35%),
          linear-gradient(180deg, #f8fbf8 0%, var(--bg) 100%);
        color: var(--ink);
      }
      main { max-width: 900px; margin: 0 auto; padding: 24px 18px 48px; }
      .card {
        background: rgba(255,255,255,0.96);
        border: 1px solid var(--line);
        border-radius: 18px;
        padding: 18px;
        margin-bottom: 16px;
        box-shadow: 0 14px 35px rgba(18, 53, 36, 0.06);
      }
      h1, h2 { margin: 0 0 12px 0; }
      .brand { display: flex; align-items: center; gap: 14px; margin-bottom: 8px; }
      .brand-mark { width: 44px; height: 44px; flex: none; }
      .brand h1 { margin: 0; }
      .brand-teal { color: #087a70; }
      p { line-height: 1.5; }
      .actions { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
      .error {
        margin: 0 0 16px 0;
        padding: 12px 14px;
        border-radius: 12px;
        border: 1px solid #d39b5f;
        background: #fff4e8;
        color: #7a3e00;
        white-space: pre-wrap;
      }
      button {
        border: 0;
        border-radius: 999px;
        padding: 11px 16px;
        font-weight: 700;
        cursor: pointer;
        background: var(--accent);
        color: white;
      }
      button:disabled { opacity: 0.6; cursor: not-allowed; }
      button.secondary { background: var(--accent-alt); }
      .code {
        font-size: 34px;
        letter-spacing: 0.12em;
        font-weight: 800;
        margin: 12px 0;
      }
      .muted { color: var(--muted); font-size: 14px; }
      details {
        margin-top: 14px;
        border-top: 1px solid var(--line);
        padding-top: 12px;
      }
      summary { cursor: pointer; font-weight: 700; color: var(--muted); }
      details h3 {
        margin: 14px 0 8px;
        font-size: 13px;
        color: var(--muted);
        text-transform: uppercase;
        letter-spacing: 0.05em;
      }
      .busy::after {
        content: " ...";
        display: inline-block;
        animation: blink 1s ease-in-out infinite;
      }
      dl { display: grid; grid-template-columns: 220px 1fr; gap: 6px 12px; margin: 0; }
      dd { margin: 0; word-break: break-word; }
      .pill {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 999px;
        background: rgba(47, 107, 73, 0.1);
        color: var(--accent);
        font-weight: 700;
      }
      img { max-width: 220px; margin-top: 10px; border: 1px solid var(--line); border-radius: 10px; }
      @keyframes blink {
        0%, 100% { opacity: 0.35; }
        50% { opacity: 1; }
      }
      @media (max-width: 700px) {
        dl { grid-template-columns: 1fr; }
        .code { font-size: 26px; }
      }
    </style>
  </head>
  <body>
    <main>
      <div id="errorBox" class="error" hidden></div>
      <div class="card">
        <div class="brand">
          <svg class="brand-mark" viewBox="0 0 100 100" role="img" aria-label="HomeTunnel logo" xmlns="http://www.w3.org/2000/svg">
            <defs>
              <mask id="bore" maskUnits="userSpaceOnUse" x="0" y="0" width="100" height="100">
                <rect x="0" y="0" width="100" height="100" fill="#fff"/>
                <circle cx="74" cy="30" r="20" fill="#000"/>
              </mask>
            </defs>
            <g mask="url(#bore)" fill="#0aa89a">
              <rect x="18" y="50" width="64" height="42"/>
              <circle cx="50" cy="50" r="32"/>
            </g>
          </svg>
          <h1>Home<span class="brand-teal">Tunnel</span></h1>
        </div>
        <p class="muted">
          Start pairing with HomeTunnel to authorize this Home Assistant device. Enrollment only completes after you approve
          the pairing code in the HomeTunnel app.
        </p>
      </div>
      <div class="card">
        <h2>Pairing</h2>
        <div class="actions">
          <button id="startBtn" type="button">Start pairing</button>
          <button id="pollBtn" class="secondary" type="button" disabled>Check approval</button>
          <button id="resetBtn" class="secondary" type="button" style="display:none">Reset pairing</button>
          <button id="restartAgentBtn" class="secondary" type="button">Restart agent (debug)</button>
        </div>
        <div id="pairingNotice" class="muted" style="margin-top:12px"></div>
        <!-- HA ingress test: Click "Start pairing", verify the pairing code appears, and approval polling only works after pairing starts. -->
        <div id="authArea" style="display:none;margin-top:14px">
          <div class="muted">Pairing code</div>
          <div class="code" id="userCode"></div>
          <div class="actions" style="margin-bottom:12px">
            <button id="copyCodeBtn" class="secondary" type="button" disabled>Copy code</button>
            <span id="codeCopyStatus" class="muted" aria-live="polite"></span>
          </div>
          <div class="muted">Open the HomeTunnel app and enter this code.</div>
          <div class="muted">Auth expires: <span id="authExp"></span></div>
          <div class="muted">Polling every <span id="pollInterval">5</span> seconds</div>
        </div>
        <div id="pairedArea" style="display:none;margin-top:14px">
          <span id="pairedPill" class="pill">Paired</span>
          <div id="pairedText" class="muted" style="margin-top:10px">This add-on is enrolled and will keep NetBird connected automatically.</div>
        </div>
      </div>
      <div class="card">
        <h2>Status</h2>
        <dl id="status"></dl>
        <details id="advancedDetails">
          <summary>Advanced details</summary>
          <h3>All status fields</h3>
          <dl id="statusAdvanced"></dl>
          <h3>Settings summary</h3>
          <dl id="settings"></dl>
        </details>
      </div>
    </main>
    <script src="./app.js" defer></script>
  </body>
</html>
"""


@app.get("/app.js")
def app_js() -> Response:
    return Response(content=APP_JS, media_type="application/javascript")


def start_proxy_resolver_loop() -> None:
    while not _proxy_stop_event.wait(PROXY_RESOLVE_INTERVAL_SECONDS):
        try:
            _proxy_resolver.resolve(force=True, reason="periodic")
        except UpstreamResolutionError as exc:
            LOG.warning("ha proxy periodic resolve failed error=%s", str(exc))


@proxy_app.on_event("startup")
async def proxy_startup_event() -> None:
    global _proxy_http_client
    install_uvicorn_log_redaction()
    ensure_data_dir()
    _proxy_stop_event.clear()
    _proxy_http_client = httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(
            connect=PROXY_CONNECT_TIMEOUT_SECONDS,
            read=PROXY_READ_TIMEOUT_SECONDS,
            write=PROXY_WRITE_TIMEOUT_SECONDS,
            pool=None,
        ),
        trust_env=False,
    )
    _proxy_resolver.resolve(force=True, reason="startup")
    thread = threading.Thread(target=start_proxy_resolver_loop, daemon=True)
    thread.start()
    LOG.info("HA proxy listening on http://%s:%s", PROXY_LISTEN_HOST, PROXY_LISTEN_PORT)


@proxy_app.on_event("shutdown")
async def proxy_shutdown_event() -> None:
    global _proxy_http_client
    _proxy_stop_event.set()
    if _proxy_http_client is not None:
        await _proxy_http_client.aclose()
        _proxy_http_client = None


@proxy_app.get("/health")
def proxy_health() -> Dict[str, Any]:
    return {"ok": True, **_proxy_resolver.snapshot()}


@proxy_app.get("/_hometunnel/upstream")
def proxy_upstream_debug() -> Dict[str, Any]:
    return {"ok": True, **_proxy_resolver.snapshot()}


@proxy_app.get("/_hometunnel/last-status")
def proxy_last_status_debug() -> Dict[str, Any]:
    diagnostics = proxy_diagnostics_snapshot()
    return {
        "ok": True,
        "selected_upstream": _proxy_resolver.snapshot(),
        "last_upstream_status": diagnostics.get("last_upstream_status"),
        "last_401": diagnostics.get("last_401"),
    }


async def resolve_proxy_upstream(force: bool = False, reason: str = "request") -> str:
    return await asyncio.to_thread(_proxy_resolver.resolve, force, reason)


def proxy_response_raw_headers(headers: httpx.Headers, upstream_base: str, public_origin: str) -> list[tuple[bytes, bytes]]:
    filtered: list[tuple[bytes, bytes]] = []
    for key, value in headers.multi_items():
        if key.lower() in HOP_BY_HOP_HEADERS:
            continue
        if key.lower() == "location":
            value = rewrite_upstream_location(value, upstream_base, public_origin)
        filtered.append((key.encode("latin-1"), value.encode("latin-1")))
    return filtered


def should_debug_auth_flow(path: str) -> bool:
    return path in {"/auth/authorize", "/auth/token"}


async def stream_proxy_request(request: Request, upstream_base: str, upstream_url: str) -> StreamingResponse:
    assert _proxy_http_client is not None
    path = request.url.path
    inbound_host = request.headers.get("host") or request.url.netloc
    forwarded = forwarded_headers(
        request.headers,
        request.client.host if request.client else None,
        request.url.scheme,
        inbound_host,
        request.url.port,
    )
    query = raw_query_string(request.scope)
    if should_debug_auth_flow(path):
        LOG.info(
            "ha proxy auth request method=%s path=%s query=%s upstream=%s forwarded_headers=%s request_headers=%s",
            request.method,
            path,
            query,
            upstream_url,
            {
                "host": forwarded.get("host"),
                "x-forwarded-host": forwarded.get("x-forwarded-host"),
                "x-forwarded-proto": forwarded.get("x-forwarded-proto"),
                "x-forwarded-for": forwarded.get("x-forwarded-for"),
                "cookie_names": cookie_header_names(forwarded["cookie"]) if forwarded.get("cookie") else [],
                "authorization_scheme": forwarded["authorization"].split(" ", 1)[0] if forwarded.get("authorization") else None,
            },
            summarize_request_headers(request.headers),
        )
    upstream_request = _proxy_http_client.build_request(
        request.method,
        upstream_url,
        headers=forwarded,
        content=request.stream(),
    )
    upstream_response = await _proxy_http_client.send(upstream_request, stream=True)
    await asyncio.to_thread(_proxy_resolver.mark_success, upstream_base)
    location = upstream_response.headers.get("location")
    record_proxy_status(
        path,
        status_code=upstream_response.status_code,
        source="upstream",
        upstream_url=upstream_url,
        location=location,
    )
    if should_debug_auth_flow(path):
        log_fn = LOG.warning if upstream_response.status_code >= 400 else LOG.info
        log_fn(
            "ha proxy auth response path=%s status=%s source=upstream location=%s response_headers=%s",
            path,
            upstream_response.status_code,
            location,
            summarize_response_headers(upstream_response.headers),
        )
    # Preserve multi-value response headers such as Set-Cookie exactly as received.
    response = StreamingResponse(
        upstream_response.aiter_raw(),
        status_code=upstream_response.status_code,
        background=BackgroundTask(upstream_response.aclose),
    )
    response.raw_headers = proxy_response_raw_headers(
        upstream_response.headers,
        upstream_base,
        public_origin_for_request(request),
    )
    return response


def is_safe_retry(request: Request) -> bool:
    return request.method.upper() in SAFE_RETRY_METHODS


@proxy_app.api_route("/", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
@proxy_app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def proxy_http_request(request: Request, full_path: str = "") -> Response:
    path = "/" + full_path.lstrip("/")
    query = raw_query_string(request.scope)

    try:
        upstream_base = await resolve_proxy_upstream(reason="http_request")
    except UpstreamResolutionError as exc:
        record_proxy_status(path, status_code=503, source="proxy", error=str(exc))
        if path == "/auth/authorize":
            LOG.warning("ha proxy auth response path=%s status=%s source=proxy error=%s", path, 503, str(exc))
        return PlainTextResponse(f"Home Assistant upstream unavailable: {exc}", status_code=503)

    attempts = 2 if is_safe_retry(request) else 1
    last_error: Optional[Exception] = None
    for attempt in range(1, attempts + 1):
        upstream_url = build_target_url(upstream_base, path, query)
        try:
            return await stream_proxy_request(request, upstream_base, upstream_url)
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            last_error = exc
            LOG.warning("ha proxy connection failure method=%s url=%s attempt=%s error=%s", request.method, upstream_url, attempt, str(exc))
            await asyncio.to_thread(_proxy_resolver.invalidate, upstream_base, str(exc))
            if attempt >= attempts:
                break
            try:
                upstream_base = await resolve_proxy_upstream(force=True, reason="http_connect_failure")
            except UpstreamResolutionError as resolve_exc:
                record_proxy_status(path, status_code=502, source="proxy", upstream_url=upstream_url, error=str(resolve_exc))
                if path == "/auth/authorize":
                    LOG.warning("ha proxy auth response path=%s status=%s source=proxy error=%s", path, 502, str(resolve_exc))
                return PlainTextResponse(f"Home Assistant upstream unavailable: {resolve_exc}", status_code=502)
        except httpx.RequestError as exc:
            LOG.warning("ha proxy request error method=%s url=%s error=%s", request.method, upstream_url, str(exc))
            record_proxy_status(path, status_code=502, source="proxy", upstream_url=upstream_url, error=str(exc))
            if path == "/auth/authorize":
                LOG.warning("ha proxy auth response path=%s status=%s source=proxy error=%s", path, 502, str(exc))
            return PlainTextResponse(f"Home Assistant proxy error: {exc}", status_code=502)

    record_proxy_status(path, status_code=502, source="proxy", upstream_url=upstream_url, error=str(last_error))
    if path == "/auth/authorize":
        LOG.warning("ha proxy auth response path=%s status=%s source=proxy error=%s", path, 502, str(last_error))
    return PlainTextResponse(f"Home Assistant upstream connect failed: {last_error}", status_code=502)


async def relay_client_to_upstream(websocket: WebSocket, upstream_socket) -> None:
    while True:
        message = await websocket.receive()
        if message["type"] == "websocket.disconnect":
            return
        if message.get("text") is not None:
            await upstream_socket.send(message["text"])
        elif message.get("bytes") is not None:
            await upstream_socket.send(message["bytes"])


async def relay_upstream_to_client(websocket: WebSocket, upstream_socket) -> None:
    async for message in upstream_socket:
        if isinstance(message, bytes):
            await websocket.send_bytes(message)
        else:
            await websocket.send_text(message)


async def proxy_websocket_session(websocket: WebSocket, full_path: str) -> None:
    path = "/" + full_path.lstrip("/")
    query = raw_query_string(websocket.scope)
    attempts = 2
    upstream_base: Optional[str] = None
    upstream_socket = None

    for attempt in range(1, attempts + 1):
        try:
            upstream_base = await resolve_proxy_upstream(force=attempt > 1, reason="websocket_request")
            upstream_socket = await websockets.connect(
                build_websocket_target_url(upstream_base, path, query),
                additional_headers=websocket_forward_headers(websocket),
                subprotocols=list(websocket.scope.get("subprotocols") or []),
                open_timeout=PROXY_WS_OPEN_TIMEOUT_SECONDS,
                close_timeout=PROXY_WS_CLOSE_TIMEOUT_SECONDS,
                max_size=None,
            )
            await asyncio.to_thread(_proxy_resolver.mark_success, upstream_base)
            break
        except UpstreamResolutionError as exc:
            LOG.warning("ha proxy websocket resolve failed path=%s error=%s", path, str(exc))
            await websocket.close(code=1013, reason="Home Assistant upstream unavailable")
            return
        except (OSError, websockets.WebSocketException) as exc:
            LOG.warning("ha proxy websocket connect failure path=%s attempt=%s error=%s", path, attempt, str(exc))
            if upstream_base:
                await asyncio.to_thread(_proxy_resolver.invalidate, upstream_base, str(exc))
            if attempt >= attempts:
                await websocket.close(code=1011, reason="Home Assistant websocket connect failed")
                return

    if upstream_socket is None:
        await websocket.close(code=1011, reason="Home Assistant websocket connect failed")
        return

    await websocket.accept(subprotocol=upstream_socket.subprotocol)
    try:
        await asyncio.gather(
            relay_client_to_upstream(websocket, upstream_socket),
            relay_upstream_to_client(websocket, upstream_socket),
        )
    except WebSocketDisconnect:
        pass
    except websockets.ConnectionClosed:
        pass
    finally:
        await upstream_socket.close()
        try:
            await websocket.close()
        except RuntimeError:
            pass


@proxy_app.websocket("/")
async def proxy_websocket_root(websocket: WebSocket) -> None:
    await proxy_websocket_session(websocket, "")


@proxy_app.websocket("/{full_path:path}")
async def proxy_websocket_path(websocket: WebSocket, full_path: str) -> None:
    await proxy_websocket_session(websocket, full_path)


if __name__ == "__main__":
    ensure_data_dir()
    validate_dns_mode_options_file()
    if len(sys.argv) > 1 and sys.argv[1] == "--validate-config":
        raise SystemExit(0)
    ensure_local_device_id()
    if len(sys.argv) > 1 and sys.argv[1] == "--netbird-agent":
        raise SystemExit(netbird_agent_loop())
    if len(sys.argv) > 3 and sys.argv[1] == "--check-bind":
        try:
            bind_check(sys.argv[2], int(sys.argv[3]))
        except Exception as exc:
            print(f"ERROR: failed to bind {sys.argv[2]}:{sys.argv[3]}: {exc}", file=sys.stderr, flush=True)
            raise SystemExit(1)
        raise SystemExit(0)
    if len(sys.argv) > 1 and sys.argv[1] == "--ha-proxy":
        uvicorn.run(proxy_app, host=PROXY_LISTEN_HOST, port=PROXY_LISTEN_PORT)
        raise SystemExit(0)
    uvicorn.run(app, host=LISTEN_HOST, port=LISTEN_PORT)

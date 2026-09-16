"""Allowlisted JSON diagnostics. Never format arbitrary messages or exceptions.

Event identifiers are a reviewed, static vocabulary. New fields require an
explicit per-event validator; strings, containers, headers and payloads are not
accepted. Unknown records become a fixed event without touching their values.
"""
import json
import logging
import sys
import threading

# Reviewed event vocabulary; no event name is derived from runtime input.
EVENTS = frozenset('''
agent_state_loaded
binding_presented_on_heartbeat
binding_received
binding_rotation_replacement
ui_request_blocked
device_auth_start_background_request_failed
device_config_fetch_failed
device_config_recovered_netbird_management_peer_id
dns_mode_on
exact_ip_conflict_detected
failed_to_delete
get_api_binding_status
get_api_heartbeat_diagnostics
get_api_ping
get_api_route_status
get_api_status
ha_proxy_auth_request
ha_proxy_auth_response
ha_proxy_connection_failure
ha_proxy_listening
ha_proxy_periodic_resolve_failed
ha_proxy_request_error
ha_proxy_upstream_rejected
ha_proxy_upstream_selected
ha_proxy_websocket_connect_failure
ha_proxy_websocket_resolve_failed
ha_route_health_status_changed
ha_route_heartbeat_queued
ha_route_heartbeat_skipped_missing_binding_id
ha_route_heartbeat_skipped_missing_credentials
ha_route_heartbeat_skipped_netbird_management_peer_id_missing
ha_route_heartbeat_skipped_netbird_not_connected
ha_route_heartbeat_skipped_unchanged
ha_route_heartbeat_success
ha_route_pending_target_cleared
ha_route_recovery_paused
ha_route_refresh_skipped_cached
ha_route_refresh_skipped_unchanged
ha_route_state_updated
ha_route_target_change_observed
ha_route_target_promoted
ha_route_update_pending_portal_reconciliation
heartbeat_binding_material_incomplete
heartbeat_diagnostics
heartbeat_network_state_built
heartbeat_network_state_missing
heartbeat_payload
heartbeat_payload_missing_target_observation
heartbeat_send_failed
heartbeat_target_observation_built
ui_trusted_client_invalid
invalid_pairing_transition
local_bypass_recommended
local_identity_cleared
local_network_context_collection_failed
missing_binding
missing_binding_before_netbird_up
mixed_identity_detected_false
mixed_identity_detected_true
netbird_agent_state_persistence_skipped_unchanged
netbird_dns_configuration
netbird_peer_startup_complete
netbird_peer_startup_failed
netbird_self_identity
netbird_status_refresh_skipped_cached
netbird_transport_degraded_state_changed
new_pairing_stored
pairing_reset_started
portal_binding_invalidation
portal_request_destination
portal_reset_cleanup
portal_reset_invalid_response
portal_reset_network_error
portal_transport_failure
post_api_agent_restart
post_api_auth_poll
post_api_auth_start
post_api_pairing_reset
preflight_memory_insufficient
preflight_memory_override
preflight_memory_passed
preflight_memory_unavailable
proxy_bind_failed
proxy_start_failed
route_target_supervisor_network_unavailable
runtime_caches_invalidated
runtime_state_refresh_skipped_unchanged
same_lan_detected
state_file_corrupted_backed_up_and_reset
state_file_corrupted_backup_failed_and_reset
state_file_unreadable_reset
subnet_overlap_detected
supervisor_api_capability
thread_exception
unraisable_exception
ui_listening
ui_refresh_live_status_skipped_while_netbird_agent_loop_is_active
ui_refresh_persistence_skipped_empty_state
uncaught_exception
unstructured_log_suppressed
upstream_connectivity
upstream_request
'''.split())

FIELD_RULES = {
    "upstream_request": {"status": lambda v: type(v) is int and 100 <= v <= 599},
    "supervisor_api_capability": {"received": lambda v: type(v) is bool},
}


def event_payload(event, fields=None):
    if type(event) is not str or event not in EVENTS:
        event = "unstructured_log_suppressed"
    result = {"event": event}
    if type(fields) is dict:
        for key, valid in FIELD_RULES.get(event, {}).items():
            value = fields.get(key)
            if valid(value):
                result[key] = value
    return result


class EventFilter(logging.Filter):
    def filter(self, record):
        # A later formatter must not append a traceback, stack, or arbitrary extra.
        payload = event_payload(record.msg, record.args)
        record.msg = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        record.args = ()
        record.exc_info = record.exc_text = record.stack_info = None
        record._hometunnel_event = payload
        return True


class EventFormatter(logging.Formatter):
    def format(self, record):
        payload = getattr(record, "_hometunnel_event", None)
        if type(payload) is dict:
            payload = event_payload(payload.get("event"), payload)
        else:
            payload = event_payload(record.msg, record.args)
        # Do not use record.levelname, logger name, pathname, or any free-form extra.
        level = {10: "debug", 20: "info", 30: "warning", 40: "error", 50: "critical"}.get(record.levelno, "error")
        return json.dumps({**payload, "level": level}, separators=(",", ":"), sort_keys=True)


_FILTER = EventFilter()


def install_event_filter(logger):
    if _FILTER not in logger.filters:
        logger.addFilter(_FILTER)


def configure_logging(level="info"):
    handler = logging.StreamHandler()
    handler.setFormatter(EventFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel({"trace": logging.DEBUG, "debug": logging.DEBUG, "info": logging.INFO, "warn": logging.WARNING, "error": logging.ERROR}.get(level, logging.INFO))
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "httpx", "httpcore", "websockets"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.propagate = True
        logger.setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").disabled = True
    logging.raiseExceptions = False
    logging.captureWarnings(True)
    # Unhandled failures otherwise bypass logging and print raw exception text.
    sys.excepthook = lambda *_: logging.getLogger("hometunnel").error("uncaught_exception")
    threading.excepthook = lambda _: logging.getLogger("hometunnel").error("thread_exception")

    sys.unraisablehook = lambda _: logging.getLogger("hometunnel").error("unraisable_exception")

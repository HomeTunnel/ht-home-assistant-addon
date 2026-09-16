# Security

Only the latest release is supported. Report suspected vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/HomeTunnel/ht-home-assistant-addon/security/advisories/new).
Do not put tokens, pairing codes, private keys, state files, raw HTTP captures or personal network details in public issues.

## Security boundaries

Home Assistant ingress authenticates access to the control panel. The add-on restricts the control API to the Supervisor and loopback socket addresses. Do not expose port 8099 directly or broaden `UI_TRUSTED_CLIENTS` to untrusted networks.
NetBird policy controls overlay access; Home Assistant authenticates proxied user requests. Keep both controls enabled. The proxy's automatic upstreams are local Supervisor service names. An explicitly configured upstream is trusted to receive Home Assistant credentials.

Credentials live under `/data` and are not part of the source distribution. Protect Home Assistant backups, the host and add-on data. The Portal receives device identity and network telemetry needed to provision and maintain the tunnel; log suppression does not remove that operational exchange.

## Logging policy

Logs contain reviewed JSON event names and only event-specific validated fields. Currently these fields are a bounded HTTP status and a capability boolean. Never add raw exception strings, URLs, request paths, IPs, routes, IDs, tokens, headers, response bodies, payload keys or arbitrary extras. New fields require validators and synthetic negative tests in `tests/test_safe_logging.py`.
Uvicorn access logging and raw NetBird output are disabled. `debug`/`trace` enable more safe application events, not raw tunnel diagnostics. Browser console messages are fixed events.
The ingress-only status panel contains operational network details for the owner; review screenshots and exported diagnostics before sharing them.

Run the unit tests, separate real-runtime integration tests, dependency audit and release secret scan before publishing. A passing scan is evidence for the inspected snapshot, not a guarantee about external services, old releases or prior logs.

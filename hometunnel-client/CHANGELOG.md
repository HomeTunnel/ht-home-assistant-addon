# Changelog

## 2.0.12 — Initial public release

- Publish a fresh GPL-3.0-only source snapshot.
- Replace free-form application, Portal-response and browser-console logs with fixed structured events.
- Exclude credentials, network addresses, routes, response bodies, headers and exception text from add-on logs; suppress raw NetBird output.
- Remove public proxy diagnostics and automatic shared-LAN mDNS upstream fallback.
- Preserve per-peer P2P/relayed heartbeat reporting from 2.0.11.
- Update and hash-lock Python dependencies; add security regression tests and release checks.
- Update the base image and rebuild NetBird with patched gRPC; remove the unused inherited tempio utility.

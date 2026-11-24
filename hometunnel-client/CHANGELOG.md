# Changelog

## 2.1.0 — Homeview

- Opt in from the add-on to share selected Home Assistant, entity, battery and LAN TCP checks with your home's Homeview in the portal. Reporting works while NetBird is disconnected.
- Review the labels and checks before sharing. Changing the pairing invalidates an open sharing preview.
- LAN checks skip the connection when the permitted network or route cannot be determined and show an unknown result.

## 2.0.13 — Initial public release

- Discover Core upstream IP, port and TLS from authenticated Supervisor information, preserving legacy port 8123 support.
- Keep the proxy running during initial Core unavailability and recover through periodic resolution.

- Publish a fresh GPL-3.0-only source snapshot.
- Replace free-form application, Portal-response and browser-console logs with fixed structured events.
- Exclude credentials, network addresses, routes, response bodies, headers and exception text from add-on logs; suppress raw NetBird output.
- Remove public proxy diagnostics and automatic shared-LAN mDNS upstream fallback.
- Preserve per-peer P2P/relayed heartbeat reporting from 2.0.11.
- Update and hash-lock Python dependencies; add security regression tests and release checks.
- Update the base image and rebuild NetBird with patched gRPC; remove the unused inherited tempio utility.

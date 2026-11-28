# Changelog

## 2.1.5 — Homeview monitoring selections

- Show and enforce up to five Home Assistant devices and three local TCP services. Checks from the same device use one device slot.
- Suggest the Home Assistant device name as the shared label, with a custom label option and privacy validation during review.
- Keep draft selections through discovery refreshes, temporary Core outages, and expired confirmations.
- Preserve over-limit selections on upgrade and pause monitoring until a compliant selection is reviewed and confirmed.

## 2.1.4 — Homeview label compatibility

- Check shared labels for network addresses during preview, confirmation and reuse of saved settings.
- Stop repeating a rejected Homeview registration and let the owner correct and confirm the settings.

## 2.1.3 — Homeview privacy and arm64 build

- Cross-compile NetBird for arm64 without emulating the compiler that crashed during the 2.1.2 build.
- Keep discovered names local. Enter a shared label without IP addresses or hostnames before enabling a new entity check.

## 2.1.2 — Homeview V2

- Choose available Home Assistant entities from a searchable device picker. Review the shared labels and choose whether to include supported values such as door, light, switch or battery status.
- Enable the Home Assistant API check separately from entity monitoring and local TCP service checks.
- Activate Homeview from the add-on when the portal owner grants permission during pairing. Existing V1 selections keep their sharing scope.

## 2.1.1 — TLS trust store update

- Update the Python certificate trust bundle used for Homeview's HTTPS connection to the portal. The updated bundle removes the affected emSign root certificates.

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

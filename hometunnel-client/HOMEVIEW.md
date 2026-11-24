# Homeview V1 for HomeTunnel Client

Homeview is off on a new installation. Pair the add-on, enable monitoring
for its home in the HomeTunnel portal, then open **HomeTunnel → Homeview**
in Home Assistant. Select checks using exact entity IDs from **Developer
tools → States**, or select a single TCP port on a device you manage.
Review the approved labels and check types before enabling sharing.

The local setup always includes a Home Assistant API check. Optional
checks cover entity availability, connectivity binary sensors, battery
percentage sensors, battery binary sensors, and explicitly selected TCP
ports. Availability is the availability of the entity in Home Assistant.
A connection to a port only shows that the port accepted TCP. Old
battery readings retain their source timestamp when Home Assistant
provides it. The portal determines when to open and resolve issues.

The add-on keeps entity IDs, addresses, ports, and the Supervisor token
on the device. Owner-approved labels, opaque monitor IDs, normalized
results, check timestamps, and battery percentages are the Homeview
observation data sent to the portal. No history backlog is sent. Stopping
sharing stops local checks immediately. The add-on sends a disabled
manifest when it can reach the portal. Selecting a different entity or
endpoint creates a new opaque ID. After a pairing reset or a device, home,
binding, or paired-origin change, configure local selections again.

## Compatibility

The Homeview support target is Home Assistant OS on the add-on's
existing aarch64 and amd64 architectures, with **Home Assistant Core
2024.4 or newer** and Supervisor providing the Core proxy and
network information described below. Use a currently maintained HAOS
and Core release for production. The 2024.4 floor is based on the
state API and the introduction of *last_reported*. That field is optional
in the add-on because its availability and cadence vary by device and
Core response. Homeview uses the existing manifest permissions and
leaves the minimum install version for the tunnel as it was.

This range is the implementation target. The checks below must pass on
real HAOS before claiming version or hardware coverage. A Core-only
installation has no Supervisor proxy. TCP checks require the standard
HAOS add-on bridge and an unambiguous primary RFC1918 IPv4 LAN.
Targets must be inside that LAN and its /24 cap, excluding network and
broadcast addresses, host addresses, nameservers, gateways, and the
Supervisor network. A missing LAN boundary or non-bridge route yields
a configuration status. TCP checks do not establish an overlay route.

- [Supervisor communication](https://contributors.home-assistant.io/apps/guides/communication/)
- [Supervisor network info](https://contributors.home-assistant.io/apps/supervisor-api/host/#get-networkinfo)
- [Core 2024.4](https://www.home-assistant.io/blog/2024/04/03/release-20244/)
- [Core state REST API](https://contributors.home-assistant.io/core/internals/rest-api/#get-apistatesentity_id)

## Portal contract

The protocol uses outbound HTTPS to the persisted paired portal origin,
with certificate verification, disabled redirects, and no proxy environment
overrides. A local opt-in plus a server session and current policy lease
are required to sample. Retries reuse the serialized payload. Restarting
the collector obtains a fresh session and starts its sequence again.
Observations and retry bytes are kept in memory. The scoped local
selection file is private to the add-on.

The copies under tests/fixtures/homeview_v1 are the schema and device API
fixtures from the portal's [Homeview V1 contract][contract], commit
b1669db1d341313cf5fd15dcb30556b06e60a493. Future changes must update the
portal contract and refresh the copies together.

[contract]: https://github.com/rafyo127/HomeTunnel/tree/b1669db1d341313cf5fd15dcb30556b06e60a493/hometunnel-portal/contracts/homeview/v1

## Automated verification

Use Python 3.12 and the hash-pinned requirements as described in
[CONTRIBUTING.md](CONTRIBUTING.md). The unit suite checks the exact
device fixture payloads, freshness, retry behavior, consent, private
settings, entity semantics, and LAN containment. The integration suite
uses the installed HTTP and ingress packages with simulated responses.
It checks ingress authorization, local consent controls, timeout
isolation, and refusal to forward redirect credentials.

## Live HAOS matrix

| Scenario | Expected observation |
| --- | --- |
| Core 2024.4 floor and current stable Core on HAOS aarch64 and amd64 | Protected ingress loads, Core proxy returns selected states, optional source timestamps work |
| NetBird daemon stopped and portal HTTPS available | Homeview continues reporting while tunnel status separately degrades |
| Core restart, then Core recovery | HA API becomes unavailable, dependent entity probes pause, and the portal clears incidents after fresh evidence |
| Sleeping sensor and percentage or binary low battery | Old source timestamp remains visible when supplied, and only the selected battery signal is sent |
| Missing or renamed entity | Configuration needs attention, with no inferred recovery |
| Local service on the primary wired or Wi-Fi LAN | IPv4 socket is bound to the standard add-on bridge, accepts only the configured host and port, and sends no payload |
| Outside-LAN, gateway, DNS, Supervisor, or overlay destination | Configuration status and no TCP connection |
| Portal outage and prolonged lease lapse | Sampling stops by lease expiry, then resumes after fresh portal consent without a backlog |
| Local disable during a slow probe, followed by re-pairing | In-flight work stops, a disabled manifest is sent if possible, and selections are cleared on new pairing |
| Old portal or old add-on | Normal pairing and tunnel operation continue, with Homeview unavailable until both sides support it |

Run this matrix in an HAOS test home before a release. Mocked test runs
do not establish performance on constrained devices or Linux bridge
routing behavior.

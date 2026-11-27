# Homeview for HomeTunnel Client

Homeview starts off on a new installation. Pair the add-on and open
**HomeTunnel → Homeview** from an administrator session in Home Assistant.
If the portal owner authorized activation during pairing, confirming the
local sharing preview activates monitoring. Other homes need approval in
the portal. A portal pause or deletion takes precedence over local consent.

- **Devices and entities** lists available, enabled entities from paired
  devices. Search by device or entity name, then select each entity you want
  to monitor. Each new selection includes availability. You can also share
  an explicitly supported value, such as a closed contact, an off light
  or switch, or a low battery reading. Existing selections remain editable
  when they become unavailable.
- **Home Assistant API** sets a separate reachability check. Existing
  installations keep their setting. Turning it off still lets selected
  entities report their own observations.
- **Local TCP services** accepts an explicit private IPv4 address and port.
  The check shows whether the port accepted a connection.

Review the shared labels, kinds, and battery thresholds before enabling or
changing monitoring. The preview expires after two minutes and is scoped to
the administrator, pairing, and saved selection revision. Stop sharing
locally to halt the checks and queue a disabled manifest. If Core is down
and local administrator authority cannot be confirmed, pause from the portal.

Discovery uses fixed read-only Supervisor WebSocket calls. The picker
allows up to 8 MiB per response and 12,000 rows per list, caches the filtered
inventory for 60 seconds, and shows 40 results per page. Exceeding a limit
produces an explicit error. The 64 KiB report limit applies independently.
Only the local administrator sees the discovery results. The portal
receives approved labels, random monitor/group IDs, normalized observations
and timestamps. It confirms incidents from the reports.

Selected V2 entities retain their Home Assistant registry identity locally.
Checks resolve it to the current entity ID, verify the mapping again after
reading, and keep the same opaque ID through a rename. A different registry
identity requires a new selection. Upgraded V1 selections retain their
previous labels, IDs, targets and sharing scope. V1 never stored registry
identity, so replace a legacy entity selection with an explicit picker
selection to opt in to registry-based rename and replacement handling.

## Compatibility

The Homeview support target is Home Assistant OS on the add-on's
existing aarch64 and amd64 architectures, with **Home Assistant Core
2024.4 or newer** and a maintained Supervisor that provides the Core proxy,
trusted ingress user IDs and network information. V2 verifies membership
against Core’s user records using the ID inserted by the Supervisor. An
environment without verifiable ingress identity cannot change local consent.
Use a currently maintained HAOS and Core release for production. The 2024.4 floor is based on the
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
Supervisor network. If the add-on cannot determine the LAN or read the route,
it skips the connection and reports an unknown result. A confirmed excluded
address or non-bridge route yields a configuration error.

- [Supervisor communication](https://contributors.home-assistant.io/apps/guides/communication/)
- [Supervisor network info](https://contributors.home-assistant.io/apps/supervisor-api/host/#get-networkinfo)
- [Core 2024.4](https://www.home-assistant.io/blog/2024/04/03/release-20244/)
- [Core state REST API](https://contributors.home-assistant.io/core/internals/rest-api/#get-apistatesentity_id)

## Portal contract

The add-on negotiates V2 before any V2 write. The copies under
`tests/fixtures/homeview_v2` come from portal commit
`8ac17a7b16cb901e9e53ad483c998f62793cfc05`, contract revision **2.0.0**.
The existing V1 fixtures remain under `tests/fixtures/homeview_v1`.

The collector sends outbound HTTPS to the persisted paired portal origin
with certificate verification and redirects disabled. A current portal
lease and a local sharing decision are both required to report. Activation
uses the currently approved grant plus the persisted local selection
revision as its retry key. An older portal accepts V1-compatible checks
when the separate HA API check is on. Contact, light and switch values
and setups without the HA API check require V2.

Both versions reject IP addresses, address-like hostnames, and network
URLs in shared labels, including URLs with single-label hosts. Address
checks use Unicode NFKC normalization and preserve approved display text.
The add-on also screens for pasted credentials, entity IDs, and private
local identifiers. If a saved label needs review, the add-on keeps the
selection and stops Homeview reporting until the labels are corrected
through **Review sharing** and confirmed. TCP targets and Home Assistant
interface access keep their existing behavior.

An HTTP 400 from manifest registration stops Homeview checks and retries
for that local pairing and selection in the running collector. Review the
shared labels and checks, then confirm any corrections to resume. Local
disable still stops checks and may send a new empty manifest.

A missing or replaced entity, a returned unknown state, an explicit
unavailable state, and inability to reach Core produce distinct local
diagnostics. The published portal can display a general Core message
while it suppresses dependent checks, including cases where the registry
no longer resolves any selected entity and no selected state request can
provide reachability evidence. An unchanged sleeping sensor's source
timestamp remains visible where the integration provides it.

## Automated verification

Use Python 3.12 and the hash-pinned requirements in
[CONTRIBUTING.md](CONTRIBUTING.md). Unit and simulated runtime tests cover
discovery filtering and pagination, state normalization, registry renames
and replacement races, preview binding, explicit admin checks, version
negotiation, grant retries, TCP-only reporting, and reporting with NetBird
disconnected. The fixture copies support offline validation with a Draft
2020-12 JSON Schema validator.

## Live HAOS matrix

| Scenario | Expected observation |
| --- | --- |
| Core 2024.4 floor and current stable Core on HAOS aarch64 and amd64 | Administrator ingress loads, non-admin ingress is denied, Core proxy returns registry and selected states |
| Home with duplicate device names and a large registry | Available entities are distinguishable, search and paging work, and capped discovery displays an error |
| Contact, light and switch | Closed and Off remain valid current values and only selected signals appear in Overview |
| Rename and replacement at the same entity address | Rename follows the same registry ID, replacement requires fresh approval |
| HA API toggle off with entity monitoring | No standalone reachability probe, entity reads supply optional Core evidence |
| HA API toggle off with TCP only | Local TCP checks continue without reading Core |
| Owner grant, local consent, pause and deletion | Only the approved grant activates monitoring, paused or deleted homes refuse queued retries |
| NetBird daemon stopped and portal HTTPS available | Homeview continues reporting while tunnel status separately degrades |
| Core restart, then Core recovery | HA API becomes unavailable, dependent entity probes pause, and the portal clears incidents after fresh evidence |
| Sleeping sensor and percentage or binary low battery | Old source timestamp remains visible when supplied, and only the selected battery signal is sent |
| Missing or renamed entity | Configuration needs attention, with no inferred recovery |
| Local service on the primary wired or Wi-Fi LAN | IPv4 socket is bound to the standard add-on bridge, accepts only the configured host and port, and sends no payload |
| Outside-LAN, gateway, DNS, Supervisor, or overlay destination | Configuration status and no TCP connection |
| Supervisor network information unavailable | TCP status is unknown and the add-on skips the connection |
| First sharing preview open during re-pairing to another home | Saving the old preview is rejected and the new home requires a fresh review |
| Portal outage and prolonged lease lapse | Sampling stops by lease expiry, then resumes after fresh portal consent without a backlog |
| Local disable during a slow probe, followed by re-pairing | In-flight work stops, a disabled manifest is sent if possible, and selections are cleared on new pairing |
| Old portal or old add-on | Normal pairing and tunnel operation continue, with Homeview unavailable until both sides support it |

Run this matrix in an HAOS test home before a release. Mocked test runs
do not establish performance on constrained devices or Linux bridge
routing behavior.

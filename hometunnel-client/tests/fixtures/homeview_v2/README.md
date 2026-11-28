# Homeview wire contract v2

Revision **2.0.0**. The JSON Schema uses Draft 2020-12 and `$defs` for each
document. Fixtures contain synthetic IDs. The fixture filenames
`configBeforeActivation` and `config` both use the config definition.

## Negotiation and routes

Send `X-Homeview-Version: 2` to the V1 routes for V2 responses and requests.
No header (or `1`) selects V1. A supported portal sets `X-Homeview-Version`
on successful JSON responses. On a V1 portal this header is absent and
config returns `schemaVersion: 1`. Discover support with GET config before
any V2 write. A 404 means the feature is unavailable and a 406 rejects
unknown protocol versions. Existing credentials, rate limits, timestamps,
leases, payload limits, replay rules and history pagination apply.

| Method and path | V2 request → response |
| --- | --- |
| GET /api/devices/:deviceId/homeview/config | — → config |
| POST /api/devices/:deviceId/homeview/activate | activationRequest → config |
| PUT /api/devices/:deviceId/homeview/monitors | manifestRequest → config |
| POST /api/devices/:deviceId/homeview/reports | reportRequest → reportResponse |
| GET /api/homeview | — → aggregate |
| GET /api/homes/:homeId/homeview/history | — → history |
| PATCH /api/homes/:homeId/homeview/settings | settings → settings |
| DELETE /api/homes/:homeId/homeview/data | — → 204 |

Activation uses the same device bearer and durable binding header as config.
After local admin approval, send the current non-null activationGeneration
and a unique request ID. Retry the same bytes on uncertainty. A successful
activation returns a consentGeneration for manifest registration. Repeating
the accepted activation returns current config while its grant remains
valid. Pause and delete revoke authorization and supersede pending writes.
`owner_confirmation_required` indicates an existing home without a valid
pairing grant or active legacy consent. An explicit owner enable resumes
collection and issues new server consent. Always continue to honor local
disable. Credentials, binding and home scope are derived server-side.

## Monitors and reports

An enabled manifest contains 1–50 unique monitor IDs and at most one ha_api.
A disabled manifest contains zero checks. All entity monitors carry an opaque
entityGroupId. An optional opaque deviceGroupId groups selected siblings.
Only entity monitors carry these IDs. Each entity group has at most one
availability and one typed signal. A typed-only group is permitted for
migration and individual status selections. IDs are randomly generated
locally. Never send HA IDs, addresses, friendly names without owner preview,
registry attributes or arbitrary state strings.
The server rejects labels containing IP addresses, network URLs or
address-like hostnames (including `.local`) with `invalid_payload`. It checks
address forms after Unicode NFKC normalization and preserves accepted label
text. This semantic rule applies in addition to the JSON Schema.

Each report contains one observation per selected monitor, with the source
and result constrained by its kind. Entity availability is independent of
the typed value. For contact, light and switch monitors use respectively
open/closed, on/off and on/off. These values update only the latest state.
Connectivity accepts connected/disconnected, binary battery low/normal,
and percentage battery reading with a finite 0–100 batteryPercent. A failed
or missing entity read reports unknown or configuration_error with an
allowlisted reason. HA's explicitly unavailable state is reported as
unavailable on the availability monitor. Never infer availability from an
old source timestamp. If a report has entity monitors and no ha_api, require
entityApiStatus from actual Core request evidence and no separate HA probe.
Use responding if Core responded to a selected state request (including a
recognized missing-entity result), unavailable if no such response was
obtained. Omit entityApiStatus otherwise. Dependency suppression and the
one-minute recovery grace apply in both cases. TCP is independent.

V2 battery defaults are low below 20 and recovered at 25 or higher.
A custom threshold uses the same comparison and a five-point recovery band.
Reused V1 percentage monitor IDs keep the inclusive low boundary for the
same binding and threshold. No version upgrade expands existing selections.
New sessions reset confirmation evidence. Previously accepted values of
unchanged monitors can appear as last_known until a fresh report is accepted.
Refresh and duplicate submissions do not advance receipt time. Stale data
always appears as last_known. Only health transitions appear in history.

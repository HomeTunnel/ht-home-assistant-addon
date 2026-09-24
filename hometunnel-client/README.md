# HomeTunnel Client

Securely access your Home Assistant from anywhere. This add-on connects your home to your HomeTunnel account over a private, encrypted tunnel — no port forwarding, no public exposure, no manual VPN setup. Pair once and it stays connected.

## How it works

1. Start the add-on and open the **HomeTunnel** panel in the sidebar.
2. Click **Start pairing** and copy the pairing code.
3. Enter the code in the HomeTunnel app to approve this device.

The add-on enrolls automatically after approval and reconnects on its own after restarts and network changes.

## Requirements

- **2 GB RAM minimum.** HomeTunnel runs alongside Home Assistant Core and your other add-ons. On 1 GB hardware — notably the **Raspberry Pi 3** — the combined memory use exhausts RAM and can freeze the whole system. **These devices are not supported**, and the add-on will refuse to start on hosts with too little memory (see `allow_low_memory` below). This matches Home Assistant OS's own 2 GB minimum. Recommended hardware: Raspberry Pi 4/5, Home Assistant Green/Yellow, or an x86 mini PC.

## Configuration

No setup is required — everything is provisioned automatically when you pair.

| Option | Default | Description |
| --- | --- | --- |
| `log_level` | `info` | Structured event verbosity (`trace`, `debug`, `info`, `warn`, `error`). Raw tunnel output is disabled at every level. |
| `allow_low_memory` | `false` | Bypass the startup memory check on hosts below the 2 GB minimum. **At your own risk** — under-provisioned hosts may run out of memory and become unresponsive. |

## Links

- [HomeTunnel](https://my.hometunnel.io)
- [Issues](https://github.com/HomeTunnel/ht-home-assistant-addon/issues)

## Install

Add this repository URL to **Settings → Add-ons → Add-on Store → Repositories**:
`https://github.com/HomeTunnel/ht-home-assistant-addon`. Install HomeTunnel Client, start it, and open the panel.

## Privacy and support

Logs use fixed JSON events and exclude credentials, IP addresses, routes, request URLs, headers, response bodies and exception text. `preflight_memory_insufficient` means the host failed the memory requirement above. The owner-only status panel still shows network details needed to operate the tunnel; inspect diagnostics before sharing them. Existing logs and backups from earlier versions are not erased by upgrading.

This repository contains the HAOS client; the HomeTunnel Portal and management services are separate and are not included or audited here.

## License and development

GPL-3.0-only. See [LICENSE](LICENSE), [third-party notices](NOTICE.md), [contributing](CONTRIBUTING.md), [security policy](SECURITY.md) and [changelog](CHANGELOG.md).

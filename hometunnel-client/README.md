# HomeTunnel Client

Securely access your Home Assistant from anywhere. This add-on connects your home to your HomeTunnel account over a private, encrypted tunnel — no port forwarding, no public exposure, no manual VPN setup. Pair once and it stays connected.

## How it works

1. Start the add-on and open the **HomeTunnel** panel in the sidebar.
2. Click **Start pairing** and copy the pairing code.
3. Enter the code in the HomeTunnel app to approve this device.

The add-on enrolls automatically after approval and reconnects on its own after restarts and network changes.

## Requirements

- **2 GB RAM minimum.** HomeTunnel runs alongside Home Assistant Core and your other add-ons. On 1 GB hardware — notably the **Raspberry Pi 3** — the combined memory use exhausts RAM and can freeze the whole system, so the Pi 3 is **not supported** and the add-on will not install on it. This matches Home Assistant OS's own 2 GB minimum. Recommended hardware: Raspberry Pi 4/5, Home Assistant Green/Yellow, or an x86 mini PC.

## Configuration

No setup is required — everything is provisioned automatically when you pair.

| Option | Default | Description |
| --- | --- | --- |
| `log_level` | `info` | Tunnel log verbosity (`trace`, `debug`, `info`, `warn`, `error`). Use `debug` when reporting an issue. |
| `allow_low_memory` | `false` | Bypass the startup memory check on hosts below the 2 GB minimum. **At your own risk** — under-provisioned hosts may run out of memory and become unresponsive. |

## Links

- [HomeTunnel](https://my.hometunnel.io)
- [Issues](https://github.com/HomeTunnel/ht-home-assistant-addon/issues)

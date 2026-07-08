# HomeTunnel Client

Securely access your Home Assistant from anywhere. This add-on connects your home to your HomeTunnel account over a private, encrypted tunnel — no port forwarding, no public exposure, no manual VPN setup. Pair once and it stays connected.

## How it works

1. Start the add-on and open the **HomeTunnel** panel in the sidebar.
2. Click **Start pairing** and copy the pairing code.
3. Enter the code in the HomeTunnel app to approve this device.

The add-on enrolls automatically after approval and reconnects on its own after restarts and network changes.

## Configuration

No setup is required — everything is provisioned automatically when you pair.

| Option | Default | Description |
| --- | --- | --- |
| `log_level` | `info` | Tunnel log verbosity (`trace`, `debug`, `info`, `warn`, `error`). Use `debug` when reporting an issue. |

## Links

- [HomeTunnel](https://my.hometunnel.io)
- [Issues](https://github.com/HomeTunnel/ht-home-assistant-addon/issues)

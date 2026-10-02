# HomeTunnel for Home Assistant

Connect your Home Assistant to your HomeTunnel account over a private, encrypted tunnel.

## Install HomeTunnel

[![Add HomeTunnel to Home Assistant](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2FHomeTunnel%2Fht-home-assistant-addon)

1. Click the badge above to open Home Assistant's **Add repository** dialog with the HomeTunnel repository URL already filled in.
2. If prompted, enter your Home Assistant instance address. Your browser must be able to reach that instance; sign in to Home Assistant if needed.
3. Confirm adding the repository, then find **HomeTunnel Client** in the app/add-on store and click **Install**.
4. Start HomeTunnel Client and open the **HomeTunnel** panel in the sidebar.
5. Click **Start pairing**, copy the pairing code, and enter it in the [HomeTunnel app](https://my.hometunnel.io) to approve this device.

The shortcut removes the need to copy and paste the repository URL. It does not add the repository or install HomeTunnel without your confirmation.

### Requirements

- Home Assistant OS with access to the app/add-on store. Home Assistant Container does not support apps/add-ons.
- At least **2 GB RAM**. See the [HomeTunnel Client documentation](hometunnel-client/README.md) for hardware requirements and configuration.
- The [My Home Assistant integration](https://www.home-assistant.io/integrations/my/) must be enabled for the shortcut to work.

### Manual installation

If the shortcut does not work, open **Settings → Apps → App store → Repositories** (called **Add-ons → Add-on Store** on older versions), add the following URL, and then install **HomeTunnel Client**:

```text
https://github.com/HomeTunnel/ht-home-assistant-addon
```

## Documentation and support

- [HomeTunnel Client documentation](hometunnel-client/README.md)
- [HomeTunnel](https://my.hometunnel.io)
- [Report an issue](https://github.com/HomeTunnel/ht-home-assistant-addon/issues)

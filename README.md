# tapoctl

Small Rust CLI for controlling Tapo plugs on the local network.

This is deliberately simple: it stores your Tapo account username, stores the password in the OS keyring, keeps a small local device registry, then uses the unofficial Rust `tapo` crate to talk to each device by LAN IP address.

## Install locally

```bash
cargo install --path .
```

Or run it from the checkout while developing:

```bash
cargo run -- --help
```

## Set up credentials

```bash
tapoctl login --username you@example.com
```

The password is read through a hidden terminal prompt. It is not accepted as a command-line argument because command-line arguments can end up in shell history and process listings.

Credential storage:

- Username and device entries: `~/.config/tapoctl/config.toml`
- Password: OS keyring entry under service `dev.kieran.tapoctl`
- Config file permissions on Unix: `0600`

## Discover devices

Discovery uses the Tapo crate's LAN discovery stream. It still needs your stored Tapo credentials because the crate authenticates each discovered device before returning full device info.

Run discovery without arguments to scan the broadcast targets derived from your local IPv4 interfaces:

```bash
tapoctl discover
```

For example, on a machine with `192.168.1.42/24`, this scans `192.168.1.255`. If no usable local interface can be found, it falls back to `255.255.255.255`.

You can still pass a subnet, subnet broadcast address, or a known device IP explicitly:

```bash
tapoctl discover 192.168.1.0/24
tapoctl discover 192.168.1.255
tapoctl discover 192.168.1.50
```

IPv4 CIDR targets are converted to the subnet broadcast address before scanning, so `192.168.1.0/24` scans `192.168.1.255`. The older `--target` flag still works if you already have scripts using it.

When discovery runs in an interactive terminal, supported unconfigured plugs are shown in a checkbox prompt after the scan. Press <kbd>Space</kbd> to toggle devices and <kbd>Enter</kbd> to add the selected devices to `~/.config/tapoctl/config.toml`.

For scripts, or if you already know you want every supported unconfigured plug, use `--add-supported`:

```bash
tapoctl discover 192.168.1.0/24 --add-supported
```

To keep discovery list-only in an interactive terminal:

```bash
tapoctl discover --no-interactive
```

Supported discovered models are added with a safe name derived from the device nickname. Existing configured IP addresses are skipped.

Discovery hides per-address errors by default so a noisy subnet does not drown out useful results. To print those errors:

```bash
tapoctl discover 192.168.1.0/24 --show-errors
```

## Add a device manually

Give the plug a stable LAN IP first, usually with a DHCP reservation on the router.

```bash
tapoctl devices add desk --ip 192.168.1.50 --model p110
```

Supported models for this first version:

- `p100`
- `p105`
- `p110`
- `p115`

List configured devices:

```bash
tapoctl devices list
```

Remove a device:

```bash
tapoctl devices remove desk
```

## Control a plug

Check that the stored credentials work against a configured plug:

```bash
tapoctl check desk
```

This prints `auth ok` only after the CLI loads the password from the OS keyring, authenticates to the local device, and reads device info.

```bash
tapoctl on desk
tapoctl off desk
tapoctl toggle desk
tapoctl status desk
```

Use a shorter timeout if a device is offline and you do not want to wait for the default 30 seconds:

```bash
tapoctl --timeout-seconds 5 status desk
```

## Limits

- This does not fetch a cloud inventory from TP-Link. Discovery is LAN-only and depends on broadcast or unicast access from the machine running `tapoctl`.
- Tapo is still an unofficial API, so firmware updates can break this.
- On Linux this build uses the `keyring` crate's `linux-native` backend. If that backend is not available in the current session, `login` will fail rather than writing the password to disk.

## Library usage

`tapoctl` can also be used as a Rust library by other local services. The reusable API is centred on `TapoController`, which takes explicit credentials and exposes discovery, state reads, power control, toggling, and energy snapshots for supported energy-monitoring plugs.

```rust,no_run
use tapoctl::{DeviceConfig, DeviceModel, TapoController, TapoCredentials};

# #[tokio::main]
# async fn main() -> anyhow::Result<()> {
let controller = TapoController::new(TapoCredentials {
    username: "you@example.com".to_string(),
    password: "tapo-password".to_string(),
});

let device = DeviceConfig {
    ip: "192.168.1.50".parse()?,
    model: DeviceModel::P110,
};

let snapshot = controller.read_device(&device).await?;
controller.set_power(&device, !snapshot.device_on).await?;
# Ok(())
# }
```

Energy data comes from the `tapo` crate's local energy-monitoring handler for P110/P110M/P115 devices. The library currently exposes current power, today's energy/runtime, and current-month energy/runtime where the device reports those values.

## Related Projects

- [Fusebox](https://github.com/kierandrewett/fusebox): local browser control board for Tapo plugs, built on `tapoctl` discovery and control primitives.

## Development

```bash
cargo fmt
cargo test
cargo run -- --help
```

## Licence

Licensed under the Mozilla Public License Version 2.0. See [LICENSE](LICENSE).

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, ErrorKind, IsTerminal};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use clap::{Args, Parser, Subcommand};
use dialoguer::{MultiSelect, theme::ColorfulTheme};
use if_addrs::{IfAddr, get_if_addrs};
use keyring::{Entry, Error as KeyringError};
use rpassword::prompt_password;
use tapo::{ApiClient, DiscoveryResult, StreamExt};
use tapoctl::{
    Config, DeviceConfig, DeviceModel, DiscoveredDevice, DiscoveryAddCandidate, DiscoveryTarget,
    LocalIpv4Network, add_device, add_discovery_candidates, discovery_add_candidates,
    discovery_scan_targets_with_auto, discovery_targets_from_local_ipv4_networks, get_device,
    remove_device, supported_device_model,
};

const KEYRING_SERVICE: &str = "dev.kieran.tapoctl";

#[derive(Debug, Parser)]
#[command(
    name = "tapoctl",
    version,
    about = "Small local CLI for controlling Tapo plugs"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    #[arg(long, default_value_t = 30, global = true)]
    timeout_seconds: u64,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Store Tapo account credentials for later local device control.
    Login(LoginArgs),
    /// Remove the stored Tapo password and username.
    Logout,
    /// Manage locally configured Tapo devices.
    Devices {
        #[command(subcommand)]
        command: DeviceCommand,
    },
    /// Discover Tapo devices on local IPv4 networks.
    Discover(DiscoverArgs),
    /// Verify stored credentials against a configured local device.
    Check(DeviceTarget),
    /// Turn a configured device on.
    On(DeviceTarget),
    /// Turn a configured device off.
    Off(DeviceTarget),
    /// Toggle a configured device based on its current state.
    Toggle(DeviceTarget),
    /// Print the current state of a configured device.
    Status(DeviceTarget),
}

#[derive(Debug, Args)]
struct LoginArgs {
    /// Tapo account email address.
    #[arg(long)]
    username: String,
}

#[derive(Debug, Args)]
struct DiscoverArgs {
    /// Unicast, broadcast, or IPv4 CIDR target to scan. Defaults to local interface CIDRs.
    #[arg(value_name = "TARGET")]
    targets: Vec<String>,
    /// Unicast, broadcast, or IPv4 CIDR target to scan. Kept for compatibility.
    #[arg(long = "target", value_name = "TARGET")]
    target: Vec<String>,
    /// How long discovery should wait for responses. The Tapo crate accepts 1 to 60 seconds.
    #[arg(long, default_value_t = 5)]
    discovery_timeout_seconds: u64,
    /// Add supported plug models to the local device registry.
    #[arg(long)]
    add_supported: bool,
    /// Disable the interactive add prompt.
    #[arg(long)]
    no_interactive: bool,
    /// Print per-address discovery errors.
    #[arg(long)]
    show_errors: bool,
}

#[derive(Debug, Args)]
struct DeviceTarget {
    /// Name configured with `tapoctl devices add`.
    name: String,
}

#[derive(Debug, Subcommand)]
enum DeviceCommand {
    /// Add a Tapo plug by local LAN IP address.
    Add(AddDeviceArgs),
    /// List configured local devices.
    List,
    /// Remove a configured local device.
    Remove(DeviceTarget),
}

#[derive(Debug, Args)]
struct AddDeviceArgs {
    /// Local name used by tapoctl commands.
    name: String,
    /// Local LAN IP address for the device.
    #[arg(long)]
    ip: IpAddr,
    /// Device model: p100, p105, p110, or p115.
    #[arg(long)]
    model: DeviceModel,
    /// Replace an existing device with the same name.
    #[arg(long)]
    replace: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    run(Cli::parse()).await
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Login(args) => login(args)?,
        Command::Logout => logout()?,
        Command::Devices { command } => devices(command)?,
        Command::Discover(args) => discover(args, cli.timeout_seconds).await?,
        Command::Check(target) => check_auth(target.name, cli.timeout_seconds).await?,
        Command::On(target) => set_power(target.name, true, cli.timeout_seconds).await?,
        Command::Off(target) => set_power(target.name, false, cli.timeout_seconds).await?,
        Command::Toggle(target) => toggle_power(target.name, cli.timeout_seconds).await?,
        Command::Status(target) => print_status(target.name, cli.timeout_seconds).await?,
    }

    Ok(())
}

fn login(args: LoginArgs) -> Result<()> {
    let password =
        prompt_password("Tapo password: ").context("failed to read password from terminal")?;

    if password.is_empty() {
        return Err(anyhow!("password cannot be empty"));
    }

    password_entry(&args.username)?
        .set_password(&password)
        .context("failed to store Tapo password in the OS keyring")?;

    let mut config = load_config()?;
    config.username = Some(args.username.clone());
    save_config(&config)?;

    println!("Stored credentials for {}.", args.username);
    println!(
        "Password is in the OS keyring. Device config is at {}.",
        config_path()?.display()
    );
    Ok(())
}

fn logout() -> Result<()> {
    let mut config = load_config()?;

    if let Some(username) = &config.username {
        match password_entry(username)?.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => {}
            Err(error) => {
                return Err(error).context("failed to delete password from the OS keyring");
            }
        }
    }

    config.username = None;
    save_config(&config)?;
    println!("Removed stored Tapo credentials. Device entries were left in place.");
    Ok(())
}

fn devices(command: DeviceCommand) -> Result<()> {
    let mut config = load_config()?;

    match command {
        DeviceCommand::Add(args) => {
            add_device(
                &mut config,
                args.name.clone(),
                DeviceConfig {
                    ip: args.ip,
                    model: args.model,
                },
                args.replace,
            )?;
            save_config(&config)?;
            println!("Configured {} at {} as {}.", args.name, args.ip, args.model);
        }
        DeviceCommand::List => {
            if config.devices.is_empty() {
                println!(
                    "No devices configured. Add one with `tapoctl devices add NAME --ip 192.168.1.50 --model p110`."
                );
                return Ok(());
            }

            for (name, device) in config.devices {
                println!("{name}\t{}\t{}", device.ip, device.model);
            }
        }
        DeviceCommand::Remove(target) => {
            remove_device(&mut config, &target.name)?;
            save_config(&config)?;
            println!("Removed {}.", target.name);
        }
    }

    Ok(())
}

async fn discover(args: DiscoverArgs, timeout_seconds: u64) -> Result<()> {
    if !(1..=60).contains(&args.discovery_timeout_seconds) {
        return Err(anyhow!(
            "--discovery-timeout-seconds must be between 1 and 60"
        ));
    }

    let auto_targets = if args.targets.is_empty() && args.target.is_empty() {
        automatic_discovery_targets().unwrap_or_else(|error| {
            eprintln!("Could not detect local IPv4 discovery targets: {error}");
            Vec::new()
        })
    } else {
        Vec::new()
    };
    let scan_targets = discovery_scan_targets_with_auto(&args.targets, &args.target, auto_targets)?;
    let mut config = load_config()?;
    let client = authenticated_client(&config, timeout_seconds)?;

    let mut discovered_count = 0_u64;
    let mut supported_count = 0_u64;
    let mut added_count = 0_u64;
    let mut error_count = 0_u64;
    let mut discovered_devices = Vec::new();
    let mut seen_device_ips = BTreeSet::new();

    println!(
        "Starting Tapo discovery scan against {} target(s).",
        scan_targets.len()
    );

    for target in &scan_targets {
        if target.requested == target.scan_address {
            println!("Scanning {}", target.scan_address);
        } else {
            println!("Scanning {} ({})", target.requested, target.scan_address);
        }

        let mut discovery = client
            .clone()
            .discover_devices(target.scan_address.clone(), args.discovery_timeout_seconds)
            .await
            .with_context(|| {
                format!(
                    "failed to start discovery for {} ({})",
                    target.requested, target.scan_address
                )
            })?;

        while let Some(result) = discovery.next().await {
            match result {
                Ok(result) => {
                    let device = discovered_device_from_result(&result)?;

                    if !seen_device_ips.insert(device.ip) {
                        continue;
                    }

                    discovered_count += 1;
                    print_discovered_device(&device);

                    if device.supported_model.is_some() {
                        supported_count += 1;
                    }

                    discovered_devices.push(device);
                }
                Err(error) => {
                    error_count += 1;

                    if args.show_errors {
                        eprintln!("Discovery error for {}: {}", error.ip, error.source);
                    }
                }
            }
        }
    }

    let candidates = discovery_add_candidates(&config, &discovered_devices);

    if args.add_supported {
        let selected_indices = (0..candidates.len()).collect::<Vec<_>>();
        added_count =
            add_selected_discovery_candidates(&mut config, &candidates, &selected_indices)?;
    } else if should_prompt_for_discovery_adds(&args) {
        added_count = prompt_and_add_discovery_candidates(&mut config, &candidates)?;
    } else if !candidates.is_empty() {
        println!(
            "Found {} supported unconfigured device(s). Re-run with --add-supported or run in an interactive terminal to select them.",
            candidates.len()
        );
    }

    if added_count > 0 {
        save_config(&config)?;
    }

    if discovered_count == 0 {
        println!("No Tapo devices discovered.");
    }

    println!(
        "Discovery complete: {} target(s) scanned, {} unique device response(s), {} supported, {} added, {} error(s).",
        scan_targets.len(),
        discovered_count,
        supported_count,
        added_count,
        error_count,
    );

    if error_count > 0 && !args.show_errors {
        println!("Run again with --show-errors to print per-address discovery errors.");
    }

    Ok(())
}

fn should_prompt_for_discovery_adds(args: &DiscoverArgs) -> bool {
    !args.no_interactive && io::stdin().is_terminal() && io::stdout().is_terminal()
}

fn automatic_discovery_targets() -> Result<Vec<DiscoveryTarget>> {
    let networks = get_if_addrs()
        .context("failed to read local network interfaces")?
        .into_iter()
        .filter_map(|interface| match interface.addr {
            IfAddr::V4(address) => Some(LocalIpv4Network {
                name: interface.name,
                ip: address.ip,
                netmask: address.netmask,
            }),
            IfAddr::V6(_) => None,
        })
        .collect::<Vec<_>>();

    Ok(discovery_targets_from_local_ipv4_networks(&networks))
}

fn discovered_device_from_result(result: &DiscoveryResult) -> Result<DiscoveredDevice> {
    let ip = result.ip();

    Ok(DiscoveredDevice {
        ip: ip
            .parse::<IpAddr>()
            .with_context(|| format!("discovered device returned an invalid IP address: {ip}"))?,
        model: result.model().to_string(),
        nickname: result.nickname().to_string(),
        device_type: result.device_type().to_string(),
        supported_model: supported_device_model(result.model()),
    })
}

fn print_discovered_device(device: &DiscoveredDevice) {
    println!("Tapo scan report for {}", device.ip);
    println!("  Model: {}", device.model);
    println!("  Type: {}", device.device_type);
    println!("  Nickname: {}", device.nickname);

    let Some(model) = device.supported_model else {
        println!("  Control: unsupported");
        return;
    };

    println!("  Control: supported as {model}");
}

fn prompt_and_add_discovery_candidates(
    config: &mut Config,
    candidates: &[DiscoveryAddCandidate],
) -> Result<u64> {
    if candidates.is_empty() {
        println!("No supported unconfigured devices to add.");
        return Ok(0);
    }

    let labels = candidates
        .iter()
        .map(|candidate| candidate.label.as_str())
        .collect::<Vec<_>>();
    let selected_indices = MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Select devices to add (space toggles, enter confirms)")
        .items(&labels)
        .interact()
        .context("failed to read discovery add selection")?;

    add_selected_discovery_candidates(config, candidates, &selected_indices)
}

fn add_selected_discovery_candidates(
    config: &mut Config,
    candidates: &[DiscoveryAddCandidate],
    selected_indices: &[usize],
) -> Result<u64> {
    let added_names = add_discovery_candidates(config, candidates, selected_indices)?;

    for name in &added_names {
        println!("Added {name}.");
    }

    Ok(added_names.len() as u64)
}

async fn check_auth(name: String, timeout_seconds: u64) -> Result<()> {
    let config = load_config()?;
    let device = get_device(&config, &name)?;
    let client = authenticated_client(&config, timeout_seconds)?;

    match device.model {
        DeviceModel::P100 => {
            let info = client
                .p100(device.ip.to_string())
                .await?
                .get_device_info()
                .await?;
            print_auth_check(&name, &info.ip, &info.model, &info.nickname, info.device_on);
        }
        DeviceModel::P105 => {
            let info = client
                .p105(device.ip.to_string())
                .await?
                .get_device_info()
                .await?;
            print_auth_check(&name, &info.ip, &info.model, &info.nickname, info.device_on);
        }
        DeviceModel::P110 => {
            let info = client
                .p110(device.ip.to_string())
                .await?
                .get_device_info()
                .await?;
            print_auth_check(&name, &info.ip, &info.model, &info.nickname, info.device_on);
        }
        DeviceModel::P115 => {
            let info = client
                .p115(device.ip.to_string())
                .await?
                .get_device_info()
                .await?;
            print_auth_check(&name, &info.ip, &info.model, &info.nickname, info.device_on);
        }
    }

    Ok(())
}

fn print_auth_check(name: &str, ip: &str, model: &str, nickname: &str, device_on: bool) {
    println!(
        "auth ok: {name}\t{ip}\t{model}\t{nickname}\t{}",
        if device_on { "on" } else { "off" }
    );
}

async fn set_power(name: String, on: bool, timeout_seconds: u64) -> Result<()> {
    let config = load_config()?;
    let device = get_device(&config, &name)?;
    let client = authenticated_client(&config, timeout_seconds)?;

    match device.model {
        DeviceModel::P100 => {
            let handler = client.p100(device.ip.to_string()).await?;
            if on {
                handler.on().await?;
            } else {
                handler.off().await?;
            }
        }
        DeviceModel::P105 => {
            let handler = client.p105(device.ip.to_string()).await?;
            if on {
                handler.on().await?;
            } else {
                handler.off().await?;
            }
        }
        DeviceModel::P110 => {
            let handler = client.p110(device.ip.to_string()).await?;
            if on {
                handler.on().await?;
            } else {
                handler.off().await?;
            }
        }
        DeviceModel::P115 => {
            let handler = client.p115(device.ip.to_string()).await?;
            if on {
                handler.on().await?;
            } else {
                handler.off().await?;
            }
        }
    }

    println!("{} is {}.", name, if on { "on" } else { "off" });
    Ok(())
}

async fn toggle_power(name: String, timeout_seconds: u64) -> Result<()> {
    let config = load_config()?;
    let device = get_device(&config, &name)?;
    let is_on = read_power_state(&config, device, timeout_seconds).await?;

    set_power(name, !is_on, timeout_seconds).await
}

async fn print_status(name: String, timeout_seconds: u64) -> Result<()> {
    let config = load_config()?;
    let device = get_device(&config, &name)?;
    let is_on = read_power_state(&config, device, timeout_seconds).await?;

    println!("{} is {}.", name, if is_on { "on" } else { "off" });
    Ok(())
}

async fn read_power_state(
    config: &Config,
    device: &DeviceConfig,
    timeout_seconds: u64,
) -> Result<bool> {
    let client = authenticated_client(config, timeout_seconds)?;

    match device.model {
        DeviceModel::P100 => Ok(client
            .p100(device.ip.to_string())
            .await?
            .get_device_info()
            .await?
            .device_on),
        DeviceModel::P105 => Ok(client
            .p105(device.ip.to_string())
            .await?
            .get_device_info()
            .await?
            .device_on),
        DeviceModel::P110 => Ok(client
            .p110(device.ip.to_string())
            .await?
            .get_device_info()
            .await?
            .device_on),
        DeviceModel::P115 => Ok(client
            .p115(device.ip.to_string())
            .await?
            .get_device_info()
            .await?
            .device_on),
    }
}

fn authenticated_client(config: &Config, timeout_seconds: u64) -> Result<ApiClient> {
    let username = config.username.as_ref().ok_or_else(|| {
        anyhow!("no Tapo username configured. Run `tapoctl login --username you@example.com` first")
    })?;
    let password = password_entry(username)?
        .get_password()
        .context("failed to load Tapo password from the OS keyring. Run `tapoctl login` again")?;

    Ok(ApiClient::new(username, password).with_timeout(Duration::from_secs(timeout_seconds)))
}

fn password_entry(username: &str) -> Result<Entry> {
    Entry::new(KEYRING_SERVICE, username).context("failed to open OS keyring entry")
}

fn load_config() -> Result<Config> {
    let path = config_path()?;
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Config::default()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read config from {}", path.display()));
        }
    };

    toml::from_str(&text).with_context(|| format!("failed to parse config at {}", path.display()))
}

fn save_config(config: &Config) -> Result<()> {
    let path = config_path()?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("config path has no parent directory: {}", path.display()))?;

    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create config directory {}", parent.display()))?;

    let text = toml::to_string_pretty(config).context("failed to serialise config as TOML")?;
    fs::write(&path, text)
        .with_context(|| format!("failed to write config to {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to set config permissions on {}", path.display()))?;
    }

    Ok(())
}

fn config_path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("TAPOCTL_CONFIG") {
        return Ok(PathBuf::from(path));
    }

    let config_home = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(path) => PathBuf::from(path),
        None => home_dir()?.join(".config"),
    };

    Ok(config_home.join("tapoctl").join("config.toml"))
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("HOME is not set and TAPOCTL_CONFIG was not provided"))
}

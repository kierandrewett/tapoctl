use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub username: Option<String>,
    #[serde(default)]
    pub devices: BTreeMap<String, DeviceConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryTarget {
    pub requested: String,
    pub scan_address: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalIpv4Network {
    pub name: String,
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredDevice {
    pub ip: IpAddr,
    pub model: String,
    pub nickname: String,
    pub device_type: String,
    pub supported_model: Option<DeviceModel>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryAddCandidate {
    pub name: String,
    pub ip: IpAddr,
    pub model: DeviceModel,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceConfig {
    pub ip: IpAddr,
    pub model: DeviceModel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceModel {
    P100,
    P105,
    P110,
    P115,
}

impl Display for DeviceModel {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::P100 => "p100",
            Self::P105 => "p105",
            Self::P110 => "p110",
            Self::P115 => "p115",
        };

        formatter.write_str(value)
    }
}

impl FromStr for DeviceModel {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "p100" => Ok(Self::P100),
            "p105" => Ok(Self::P105),
            "p110" | "p110m" => Ok(Self::P110),
            "p115" => Ok(Self::P115),
            other => Err(anyhow!(
                "unsupported model '{other}'. Supported models: p100, p105, p110, p115",
            )),
        }
    }
}

pub fn supported_device_model(model: &str) -> Option<DeviceModel> {
    DeviceModel::from_str(model).ok()
}

pub fn discovery_scan_targets(
    positional_targets: &[String],
    flag_targets: &[String],
) -> Result<Vec<DiscoveryTarget>> {
    discovery_scan_targets_with_auto(positional_targets, flag_targets, Vec::new())
}

pub fn discovery_scan_targets_with_auto(
    positional_targets: &[String],
    flag_targets: &[String],
    auto_targets: Vec<DiscoveryTarget>,
) -> Result<Vec<DiscoveryTarget>> {
    if positional_targets.is_empty() && flag_targets.is_empty() {
        if auto_targets.is_empty() {
            return Ok(vec![normalise_discovery_target("255.255.255.255")?]);
        }

        return Ok(auto_targets);
    }

    let targets: Vec<&str> = positional_targets
        .iter()
        .chain(flag_targets.iter())
        .map(String::as_str)
        .collect();

    targets
        .into_iter()
        .map(normalise_discovery_target)
        .collect()
}

pub fn discovery_targets_from_local_ipv4_networks(
    networks: &[LocalIpv4Network],
) -> Vec<DiscoveryTarget> {
    let mut seen_scan_addresses = BTreeSet::new();
    let mut targets = Vec::new();

    for network in networks {
        let Some(prefix) = ipv4_netmask_prefix(network.netmask) else {
            continue;
        };

        if prefix >= 31
            || network.ip.is_loopback()
            || network.ip.is_unspecified()
            || network.ip.is_link_local()
        {
            continue;
        }

        let netmask = u32::from(network.netmask);
        let network_address = Ipv4Addr::from(u32::from(network.ip) & netmask);
        let scan_address = ipv4_broadcast_address(network.ip, prefix).to_string();

        if !seen_scan_addresses.insert(scan_address.clone()) {
            continue;
        }

        targets.push(DiscoveryTarget {
            requested: format!("{}:{network_address}/{prefix}", network.name),
            scan_address,
        });
    }

    targets
}

pub fn discovery_add_candidates(
    config: &Config,
    devices: &[DiscoveredDevice],
) -> Vec<DiscoveryAddCandidate> {
    let mut candidate_config = config.clone();
    let mut candidates = Vec::new();

    for device in devices {
        let Some(model) = device.supported_model else {
            continue;
        };

        if candidate_config
            .devices
            .values()
            .any(|configured_device| configured_device.ip == device.ip)
        {
            continue;
        }

        let name = discovered_device_name(
            &candidate_config,
            &device.nickname,
            &device.model,
            device.ip,
        );
        let label = format!(
            "{} ({}) at {} -> {}",
            device.nickname, device.model, device.ip, name
        );

        candidates.push(DiscoveryAddCandidate {
            name: name.clone(),
            ip: device.ip,
            model,
            label,
        });

        candidate_config.devices.insert(
            name,
            DeviceConfig {
                ip: device.ip,
                model,
            },
        );
    }

    candidates
}

pub fn add_discovery_candidates(
    config: &mut Config,
    candidates: &[DiscoveryAddCandidate],
    selected_indices: &[usize],
) -> Result<Vec<String>> {
    let mut added_names = Vec::new();

    for index in selected_indices {
        let candidate = candidates
            .get(*index)
            .ok_or_else(|| anyhow!("selected discovery candidate index {index} is out of range"))?;

        add_device(
            config,
            candidate.name.clone(),
            DeviceConfig {
                ip: candidate.ip,
                model: candidate.model,
            },
            false,
        )?;
        added_names.push(candidate.name.clone());
    }

    Ok(added_names)
}

fn normalise_discovery_target(target: &str) -> Result<DiscoveryTarget> {
    let target = target.trim();

    if target.is_empty() {
        return Err(anyhow!("discovery target cannot be empty"));
    }

    if let Some((ip, prefix)) = target.split_once('/') {
        if prefix.contains('/') {
            return Err(anyhow!("invalid IPv4 CIDR target '{target}'"));
        }

        let ip = ip
            .parse::<Ipv4Addr>()
            .with_context(|| format!("invalid IPv4 CIDR address in target '{target}'"))?;
        let prefix = prefix
            .parse::<u8>()
            .with_context(|| format!("invalid IPv4 CIDR prefix in target '{target}'"))?;

        if prefix > 32 {
            return Err(anyhow!(
                "invalid IPv4 CIDR prefix in target '{target}': expected 0 to 32"
            ));
        }

        return Ok(DiscoveryTarget {
            requested: target.to_string(),
            scan_address: ipv4_broadcast_address(ip, prefix).to_string(),
        });
    }

    let ip = target
        .parse::<IpAddr>()
        .with_context(|| format!("invalid discovery target '{target}'"))?;

    Ok(DiscoveryTarget {
        requested: target.to_string(),
        scan_address: ip.to_string(),
    })
}

fn ipv4_broadcast_address(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let host_mask = if prefix == 32 { 0 } else { u32::MAX >> prefix };

    Ipv4Addr::from(u32::from(ip) | host_mask)
}

fn ipv4_netmask_prefix(netmask: Ipv4Addr) -> Option<u8> {
    let netmask = u32::from(netmask);
    let prefix = netmask.count_ones() as u8;
    let expected = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };

    if netmask == expected {
        Some(prefix)
    } else {
        None
    }
}

pub fn discovered_device_name(config: &Config, nickname: &str, model: &str, ip: IpAddr) -> String {
    let base_name = sanitise_device_name(nickname)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| fallback_device_name(model, ip));

    unique_device_name(config, &base_name)
}

fn sanitise_device_name(value: &str) -> Option<String> {
    let mut output = String::new();
    let mut previous_was_separator = false;

    for character in value.chars().flat_map(char::to_lowercase) {
        if character.is_ascii_alphanumeric() {
            output.push(character);
            previous_was_separator = false;
            continue;
        }

        if matches!(character, '-' | '_' | ' ') && !previous_was_separator && !output.is_empty() {
            output.push('-');
            previous_was_separator = true;
        }
    }

    let trimmed = output.trim_matches('-').to_string();

    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn fallback_device_name(model: &str, ip: IpAddr) -> String {
    let model = sanitise_device_name(model).unwrap_or_else(|| "tapo".to_string());
    let ip = ip.to_string().replace(['.', ':'], "-");

    format!("{model}-{ip}")
}

fn unique_device_name(config: &Config, base_name: &str) -> String {
    if !config.devices.contains_key(base_name) {
        return base_name.to_string();
    }

    for suffix in 2.. {
        let candidate = format!("{base_name}-{suffix}");
        if !config.devices.contains_key(&candidate) {
            return candidate;
        }
    }

    unreachable!("unbounded suffix search should always return")
}

pub fn add_device(
    config: &mut Config,
    name: String,
    device: DeviceConfig,
    replace: bool,
) -> Result<()> {
    validate_device_name(&name)?;

    if !replace && config.devices.contains_key(&name) {
        return Err(anyhow!(
            "device '{name}' already exists. Re-run with --replace if this is intentional",
        ));
    }

    config.devices.insert(name, device);
    Ok(())
}

pub fn remove_device(config: &mut Config, name: &str) -> Result<DeviceConfig> {
    config
        .devices
        .remove(name)
        .ok_or_else(|| anyhow!("device '{name}' is not configured"))
}

pub fn get_device<'a>(config: &'a Config, name: &str) -> Result<&'a DeviceConfig> {
    config.devices.get(name).ok_or_else(|| {
        anyhow!("device '{name}' is not configured. Add it with `tapoctl devices add`")
    })
}

pub fn validate_device_name(name: &str) -> Result<()> {
    let is_valid = !name.is_empty()
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'));

    if is_valid {
        return Ok(());
    }

    Err(anyhow!(
        "device names must contain only ASCII letters, numbers, hyphens, and underscores",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plug(ip: &str) -> DeviceConfig {
        DeviceConfig {
            ip: ip.parse().expect("test IP should be valid"),
            model: DeviceModel::P110,
        }
    }

    fn discovered_plug(ip: &str, nickname: &str) -> DiscoveredDevice {
        DiscoveredDevice {
            ip: ip.parse().expect("test IP should be valid"),
            model: "P110".to_string(),
            nickname: nickname.to_string(),
            device_type: "Plug with Energy Monitoring".to_string(),
            supported_model: Some(DeviceModel::P110),
        }
    }

    #[test]
    fn parses_supported_models_case_insensitively() {
        assert_eq!(DeviceModel::from_str("P100").unwrap(), DeviceModel::P100);
        assert_eq!(DeviceModel::from_str("p105").unwrap(), DeviceModel::P105);
        assert_eq!(DeviceModel::from_str("P110M").unwrap(), DeviceModel::P110);
        assert_eq!(DeviceModel::from_str("p115").unwrap(), DeviceModel::P115);
    }

    #[test]
    fn rejects_unknown_models() {
        let error = DeviceModel::from_str("shelly-plug").unwrap_err();

        assert!(error.to_string().contains("unsupported model"));
    }

    #[test]
    fn maps_supported_discovery_models() {
        assert_eq!(supported_device_model("P100"), Some(DeviceModel::P100));
        assert_eq!(supported_device_model("P105"), Some(DeviceModel::P105));
        assert_eq!(supported_device_model("P110"), Some(DeviceModel::P110));
        assert_eq!(supported_device_model("P110M"), Some(DeviceModel::P110));
        assert_eq!(supported_device_model("P115"), Some(DeviceModel::P115));
        assert_eq!(supported_device_model("L530"), None);
    }

    #[test]
    fn derives_safe_names_for_discovered_devices() {
        let config = Config::default();
        let name = discovered_device_name(
            &config,
            "Desk Plug (P110)",
            "P110",
            "192.168.1.50".parse().unwrap(),
        );

        assert_eq!(name, "desk-plug-p110");
    }

    #[test]
    fn falls_back_to_model_and_ip_when_nickname_is_empty() {
        let config = Config::default();
        let name = discovered_device_name(&config, "", "P110", "192.168.1.50".parse().unwrap());

        assert_eq!(name, "p110-192-168-1-50");
    }

    #[test]
    fn avoids_name_collisions_for_discovered_devices() {
        let mut config = Config::default();
        add_device(
            &mut config,
            "desk-plug".to_string(),
            plug("192.168.1.50"),
            false,
        )
        .unwrap();

        let name = discovered_device_name(
            &config,
            "Desk Plug",
            "P110",
            "192.168.1.51".parse().unwrap(),
        );

        assert_eq!(name, "desk-plug-2");
    }

    #[test]
    fn adds_named_devices_without_replacing_existing_entries() {
        let mut config = Config::default();

        add_device(&mut config, "desk".to_string(), plug("192.168.1.50"), false).unwrap();
        let error =
            add_device(&mut config, "desk".to_string(), plug("192.168.1.51"), false).unwrap_err();

        assert!(error.to_string().contains("already exists"));
        assert_eq!(
            config.devices["desk"].ip,
            "192.168.1.50".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn replaces_named_devices_when_explicitly_requested() {
        let mut config = Config::default();

        add_device(&mut config, "desk".to_string(), plug("192.168.1.50"), false).unwrap();
        add_device(&mut config, "desk".to_string(), plug("192.168.1.51"), true).unwrap();

        assert_eq!(
            config.devices["desk"].ip,
            "192.168.1.51".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn removes_configured_devices() {
        let mut config = Config::default();
        add_device(&mut config, "desk".to_string(), plug("192.168.1.50"), false).unwrap();

        let removed = remove_device(&mut config, "desk").unwrap();

        assert_eq!(removed.ip, "192.168.1.50".parse::<IpAddr>().unwrap());
        assert!(config.devices.is_empty());
    }

    #[test]
    fn validates_device_names_for_shell_safe_lookup() {
        assert!(validate_device_name("desk_plug-1").is_ok());
        assert!(validate_device_name("desk plug").is_err());
        assert!(validate_device_name("").is_err());
    }

    #[test]
    fn defaults_discovery_to_limited_broadcast_when_no_targets_are_given() {
        let targets = discovery_scan_targets(&[], &[]).unwrap();

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].requested, "255.255.255.255");
        assert_eq!(targets[0].scan_address, "255.255.255.255");
    }

    #[test]
    fn accepts_positional_and_flag_discovery_targets() {
        let positional = vec!["192.168.0.40".to_string()];
        let flags = vec!["192.168.0.255".to_string()];
        let targets = discovery_scan_targets(&positional, &flags).unwrap();

        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].scan_address, "192.168.0.40");
        assert_eq!(targets[1].scan_address, "192.168.0.255");
    }

    #[test]
    fn converts_ipv4_cidr_targets_to_broadcast_addresses() {
        let positional = vec!["192.168.0.0/24".to_string(), "10.42.5.10/16".to_string()];
        let targets = discovery_scan_targets(&positional, &[]).unwrap();

        assert_eq!(targets[0].requested, "192.168.0.0/24");
        assert_eq!(targets[0].scan_address, "192.168.0.255");
        assert_eq!(targets[1].requested, "10.42.5.10/16");
        assert_eq!(targets[1].scan_address, "10.42.255.255");
    }

    #[test]
    fn rejects_invalid_discovery_targets() {
        let positional = vec!["192.168.0.0/33".to_string()];
        let error = discovery_scan_targets(&positional, &[]).unwrap_err();

        assert!(error.to_string().contains("invalid IPv4 CIDR prefix"));
    }

    #[test]
    fn derives_discovery_targets_from_local_ipv4_networks() {
        let networks = vec![LocalIpv4Network {
            name: "wlan0".to_string(),
            ip: "192.168.0.42".parse().unwrap(),
            netmask: "255.255.255.0".parse().unwrap(),
        }];
        let targets = discovery_targets_from_local_ipv4_networks(&networks);

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].requested, "wlan0:192.168.0.0/24");
        assert_eq!(targets[0].scan_address, "192.168.0.255");
    }

    #[test]
    fn skips_loopback_and_point_to_point_local_ipv4_networks() {
        let networks = vec![
            LocalIpv4Network {
                name: "lo".to_string(),
                ip: "127.0.0.1".parse().unwrap(),
                netmask: "255.0.0.0".parse().unwrap(),
            },
            LocalIpv4Network {
                name: "tun0".to_string(),
                ip: "10.0.0.1".parse().unwrap(),
                netmask: "255.255.255.255".parse().unwrap(),
            },
        ];

        assert!(discovery_targets_from_local_ipv4_networks(&networks).is_empty());
    }

    #[test]
    fn uses_auto_targets_when_no_explicit_discovery_targets_are_given() {
        let auto_targets = vec![DiscoveryTarget {
            requested: "wlan0:192.168.0.0/24".to_string(),
            scan_address: "192.168.0.255".to_string(),
        }];
        let targets = discovery_scan_targets_with_auto(&[], &[], auto_targets.clone()).unwrap();

        assert_eq!(targets, auto_targets);
    }

    #[test]
    fn falls_back_to_limited_broadcast_when_no_auto_targets_are_available() {
        let targets = discovery_scan_targets_with_auto(&[], &[], Vec::new()).unwrap();

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].requested, "255.255.255.255");
        assert_eq!(targets[0].scan_address, "255.255.255.255");
    }

    #[test]
    fn builds_add_candidates_for_supported_unconfigured_discovered_devices() {
        let config = Config::default();
        let devices = vec![discovered_plug("192.168.0.40", "Lights")];
        let candidates = discovery_add_candidates(&config, &devices);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].name, "lights");
        assert_eq!(candidates[0].ip, "192.168.0.40".parse::<IpAddr>().unwrap());
        assert_eq!(candidates[0].model, DeviceModel::P110);
        assert_eq!(
            candidates[0].label,
            "Lights (P110) at 192.168.0.40 -> lights"
        );
    }

    #[test]
    fn skips_unsupported_and_already_configured_discovered_devices() {
        let mut config = Config::default();
        add_device(
            &mut config,
            "lights".to_string(),
            plug("192.168.0.40"),
            false,
        )
        .unwrap();
        let devices = vec![
            discovered_plug("192.168.0.40", "Lights"),
            DiscoveredDevice {
                ip: "192.168.0.50".parse().unwrap(),
                model: "L530".to_string(),
                nickname: "Lamp".to_string(),
                device_type: "Bulb".to_string(),
                supported_model: None,
            },
        ];

        assert!(discovery_add_candidates(&config, &devices).is_empty());
    }

    #[test]
    fn reserves_candidate_names_to_avoid_selection_collisions() {
        let config = Config::default();
        let devices = vec![
            discovered_plug("192.168.0.40", "Plug"),
            discovered_plug("192.168.0.41", "Plug"),
        ];
        let candidates = discovery_add_candidates(&config, &devices);

        assert_eq!(candidates[0].name, "plug");
        assert_eq!(candidates[1].name, "plug-2");
    }

    #[test]
    fn adds_selected_discovery_candidates() {
        let mut config = Config::default();
        let devices = vec![
            discovered_plug("192.168.0.40", "Lights"),
            discovered_plug("192.168.0.105", "Server"),
        ];
        let candidates = discovery_add_candidates(&config, &devices);
        let added_names = add_discovery_candidates(&mut config, &candidates, &[1]).unwrap();

        assert_eq!(added_names, vec!["server".to_string()]);
        assert!(!config.devices.contains_key("lights"));
        assert_eq!(
            config.devices["server"].ip,
            "192.168.0.105".parse::<IpAddr>().unwrap()
        );
    }
}

use thiserror::Error;

#[derive(Debug, Clone)]
pub struct ForwardingState {
    active: bool,
    #[cfg(target_os = "linux")]
    nft_state: Option<NftState>,
}

impl ForwardingState {
    pub fn inactive() -> Self {
        Self {
            active: false,
            #[cfg(target_os = "linux")]
            nft_state: None,
        }
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    #[cfg(target_os = "linux")]
    fn with_nft(nft_state: NftState) -> Self {
        Self {
            active: true,
            nft_state: Some(nft_state),
        }
    }

    pub fn deactivate(&mut self) {
        self.active = false;
        #[cfg(target_os = "linux")]
        {
            self.nft_state = None;
        }
    }

    #[cfg(target_os = "linux")]
    fn take_nft_state(&mut self) -> Option<NftState> {
        self.nft_state.take()
    }
}

impl Default for ForwardingState {
    fn default() -> Self {
        Self::inactive()
    }
}

#[derive(Error, Debug)]
pub enum FirewallError {
    #[error("Unsupported platform for nftables configuration")]
    Unsupported,

    #[error("Failed to detect egress interface: {0}")]
    InterfaceDetection(String),

    #[error("Command '{command}' failed: {stderr}")]
    CommandFailure { command: String, stderr: String },

    #[error("Required binary '{binary}' not found")]
    MissingBinary { binary: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

const DEFAULT_WG_CIDR: &str = "10.0.0.0/8";

pub fn wireguard_cidr_from_env() -> String {
    std::env::var("VPN9_WG_CIDR").unwrap_or_else(|_| DEFAULT_WG_CIDR.to_string())
}

pub fn wireguard_ipv6_cidr_from_env() -> Option<String> {
    match std::env::var("VPN9_WG_IPV6_CIDR") {
        Ok(value) if !value.trim().is_empty() => Some(value),
        _ => None,
    }
}

pub fn ensure_forwarding(
    wg_iface: &str,
    ipv4_cidr: &str,
    ipv6_cidr: Option<&str>,
    egress_override: Option<&str>,
) -> Result<ForwardingState, FirewallError> {
    #[cfg(target_os = "linux")]
    {
        ensure_forwarding_linux(wg_iface, ipv4_cidr, ipv6_cidr, egress_override)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (wg_iface, ipv4_cidr, ipv6_cidr, egress_override);
        tracing::info!("Skipping nftables forwarding configuration; unsupported platform");
        Ok(ForwardingState::inactive())
    }
}

pub fn teardown_forwarding(state: &mut ForwardingState) -> Result<(), FirewallError> {
    #[cfg(target_os = "linux")]
    {
        teardown_forwarding_linux(state)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = state;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
const NAT_TABLE: &str = "vpn9_nat";
#[cfg(target_os = "linux")]
const FILTER_TABLE: &str = "vpn9";
#[cfg(target_os = "linux")]
const POSTROUTING_CHAIN: &str = "vpn9_postrouting";
#[cfg(target_os = "linux")]
const FORWARD_CHAIN: &str = "vpn9_forward";

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct NftState {
    nat_v4_table_created: bool,
    nat_v6_table_created: bool,
    ipv6_enabled: bool,
    filter_table_created: bool,
}

#[cfg(target_os = "linux")]
fn ensure_forwarding_linux(
    wg_iface: &str,
    ipv4_cidr: &str,
    ipv6_cidr: Option<&str>,
    egress_override: Option<&str>,
) -> Result<ForwardingState, FirewallError> {
    let egress_iface = match egress_override {
        Some(iface) => iface.to_string(),
        None => detect_default_interface()?,
    };

    let ipv6_label = ipv6_cidr.unwrap_or("disabled");
    tracing::info!(
        interface = wg_iface,
        ipv4_cidr,
        ipv6_cidr = ipv6_label,
        egress = %egress_iface,
        "Configuring nftables forwarding rules"
    );

    let nat_v4_table_created = ensure_table_exists("ip", NAT_TABLE)?;
    ensure_chain_exists(
        "ip",
        NAT_TABLE,
        POSTROUTING_CHAIN,
        &[
            "{",
            "type",
            "nat",
            "hook",
            "postrouting",
            "priority",
            "100;",
            "policy",
            "accept;",
            "}",
        ],
    )?;
    flush_chain("ip", NAT_TABLE, POSTROUTING_CHAIN)?;
    add_rule(&[
        "add",
        "rule",
        "ip",
        NAT_TABLE,
        POSTROUTING_CHAIN,
        "oifname",
        &egress_iface,
        "ip",
        "saddr",
        ipv4_cidr,
        "masquerade",
    ])?;

    let mut nat_v6_table_created = false;
    if let Some(cidr6) = ipv6_cidr {
        nat_v6_table_created = ensure_table_exists("ip6", NAT_TABLE)?;
        ensure_chain_exists(
            "ip6",
            NAT_TABLE,
            POSTROUTING_CHAIN,
            &[
                "{",
                "type",
                "nat",
                "hook",
                "postrouting",
                "priority",
                "100;",
                "policy",
                "accept;",
                "}",
            ],
        )?;
        flush_chain("ip6", NAT_TABLE, POSTROUTING_CHAIN)?;
        add_rule(&[
            "add",
            "rule",
            "ip6",
            NAT_TABLE,
            POSTROUTING_CHAIN,
            "oifname",
            &egress_iface,
            "ip6",
            "saddr",
            cidr6,
            "masquerade",
        ])?;
    }

    let filter_table_created = ensure_table_exists("inet", FILTER_TABLE)?;
    ensure_chain_exists(
        "inet",
        FILTER_TABLE,
        FORWARD_CHAIN,
        &[
            "{", "type", "filter", "hook", "forward", "priority", "-100;", "policy", "accept;", "}",
        ],
    )?;
    flush_chain("inet", FILTER_TABLE, FORWARD_CHAIN)?;
    add_rule(&[
        "add",
        "rule",
        "inet",
        FILTER_TABLE,
        FORWARD_CHAIN,
        "iifname",
        wg_iface,
        "oifname",
        &egress_iface,
        "ct",
        "state",
        "new,established",
        "accept",
    ])?;
    add_rule(&[
        "add",
        "rule",
        "inet",
        FILTER_TABLE,
        FORWARD_CHAIN,
        "iifname",
        &egress_iface,
        "oifname",
        wg_iface,
        "ct",
        "state",
        "related,established",
        "accept",
    ])?;

    Ok(ForwardingState::with_nft(NftState {
        nat_v4_table_created,
        nat_v6_table_created,
        ipv6_enabled: ipv6_cidr.is_some(),
        filter_table_created,
    }))
}

#[cfg(target_os = "linux")]
fn teardown_forwarding_linux(state: &mut ForwardingState) -> Result<(), FirewallError> {
    if !state.is_active() {
        return Ok(());
    }

    if let Some(nft_state) = state.take_nft_state() {
        if nft_state.nat_v4_table_created {
            let _ = run_nft_command(&["delete", "table", "ip", NAT_TABLE]);
        } else {
            let _ = run_nft_command(&["flush", "chain", "ip", NAT_TABLE, POSTROUTING_CHAIN]);
        }
        if nft_state.ipv6_enabled {
            if nft_state.nat_v6_table_created {
                let _ = run_nft_command(&["delete", "table", "ip6", NAT_TABLE]);
            } else {
                let _ = run_nft_command(&["flush", "chain", "ip6", NAT_TABLE, POSTROUTING_CHAIN]);
            }
        }
        if nft_state.filter_table_created {
            let _ = run_nft_command(&["delete", "table", "inet", FILTER_TABLE]);
        } else {
            let _ = run_nft_command(&["flush", "chain", "inet", FILTER_TABLE, FORWARD_CHAIN]);
        }
    }

    state.deactivate();
    tracing::info!("Removed nftables forwarding rules");
    Ok(())
}

#[cfg(target_os = "linux")]
fn detect_default_interface() -> Result<String, FirewallError> {
    use std::process::Command;
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()?;

    if !output.status.success() {
        return Err(FirewallError::InterfaceDetection(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_default_route_device(&stdout)
        .ok_or_else(|| FirewallError::InterfaceDetection("no default route found".into()))
}

#[cfg(target_os = "linux")]
fn parse_default_route_device(routes: &str) -> Option<String> {
    for line in routes.lines() {
        if !line.starts_with("default") {
            continue;
        }
        let mut parts = line.split_whitespace();
        while let Some(part) = parts.next() {
            if part == "dev" {
                return parts.next().map(|iface| iface.to_string());
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn ensure_table_exists(family: &str, table: &str) -> Result<bool, FirewallError> {
    if run_nft_command(&["list", "table", family, table]).is_ok() {
        return Ok(false);
    }

    run_nft_command(&["add", "table", family, table])?;
    Ok(true)
}

#[cfg(target_os = "linux")]
fn ensure_chain_exists(
    family: &str,
    table: &str,
    chain: &str,
    definition: &[&str],
) -> Result<(), FirewallError> {
    if run_nft_command(&["list", "chain", family, table, chain]).is_ok() {
        return Ok(());
    }

    let mut args = vec!["add", "chain", family, table, chain];
    args.extend_from_slice(definition);
    run_nft_command(&args)
}

#[cfg(target_os = "linux")]
fn flush_chain(family: &str, table: &str, chain: &str) -> Result<(), FirewallError> {
    run_nft_command(&["flush", "chain", family, table, chain])
}

#[cfg(target_os = "linux")]
fn add_rule(args: &[&str]) -> Result<(), FirewallError> {
    run_nft_command(args)
}

#[cfg(target_os = "linux")]
fn run_nft_command(args: &[&str]) -> Result<(), FirewallError> {
    use std::process::Command;

    let nft_path = resolve_nft_binary()?;
    let output = Command::new(nft_path).args(args).output()?;
    if output.status.success() {
        return Ok(());
    }

    Err(FirewallError::CommandFailure {
        command: format!("nft {}", args.join(" ")),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    })
}

#[cfg(target_os = "linux")]
fn resolve_nft_binary() -> Result<&'static str, FirewallError> {
    use std::sync::OnceLock;

    static NFT_BIN: OnceLock<String> = OnceLock::new();

    if let Some(bin) = NFT_BIN.get() {
        return Ok(bin.as_str());
    }

    let resolved = resolve_nft_path()?;
    let _ = NFT_BIN.set(resolved);
    Ok(NFT_BIN
        .get()
        .expect("nft binary path should be set")
        .as_str())
}

#[cfg(target_os = "linux")]
fn resolve_nft_path() -> Result<String, FirewallError> {
    use std::env;
    use std::path::Path;

    if let Ok(custom) = env::var("VPN9_NFT_BIN") {
        if Path::new(&custom).is_file() {
            return Ok(custom);
        }
    }

    if let Some(path_os) = env::var_os("PATH") {
        for dir in env::split_paths(&path_os) {
            let candidate = dir.join("nft");
            if candidate.is_file() {
                return Ok(candidate.to_string_lossy().into_owned());
            }
        }
    }

    for candidate in ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"] {
        if Path::new(candidate).is_file() {
            return Ok(candidate.to_string());
        }
    }

    Err(FirewallError::MissingBinary {
        binary: "nft".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_cidr_from_env_returns_override_when_set() {
        let key = "VPN9_WG_CIDR";
        unsafe {
            std::env::set_var(key, "10.42.0.0/16");
        }
        assert_eq!(wireguard_cidr_from_env(), "10.42.0.0/16");
        unsafe {
            std::env::remove_var(key);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_default_route_device_extracts_interface() {
        let sample = "default via 192.0.2.1 dev eth0 proto dhcp metric 100 \n";
        assert_eq!(parse_default_route_device(sample), Some("eth0".into()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_default_route_device_handles_multiple_lines() {
        let sample = "10.0.0.0/8 dev wg0 proto kernel scope link src 10.0.0.2\n
default via 198.51.100.1 dev eno1 proto dhcp metric 100\n";
        assert_eq!(parse_default_route_device(sample), Some("eno1".into()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_default_route_device_returns_none_when_missing() {
        assert_eq!(parse_default_route_device("wg0 proto kernel"), None);
    }

    #[test]
    fn wireguard_ipv6_cidr_from_env_reads_value_when_set() {
        let key = "VPN9_WG_IPV6_CIDR";
        unsafe {
            std::env::set_var(key, "fd00:9::/64");
        }
        assert_eq!(
            wireguard_ipv6_cidr_from_env(),
            Some("fd00:9::/64".to_string())
        );
        unsafe {
            std::env::remove_var(key);
        }
        assert_eq!(wireguard_ipv6_cidr_from_env(), None);
    }
}

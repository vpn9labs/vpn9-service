use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::firewall::{self, ForwardingState};
use base64::Engine;
use defguard_wireguard_rs::{
    InterfaceConfiguration, Kernel, WGApi, WireguardInterfaceApi, host::Peer, key::Key,
    net::IpAddrMask,
};
use tracing::{debug, error, info, warn};
use vpn9_core::control_plane::{AgentRegistration, PeerAdd, PeerRemove};
use zeroize::{Zeroize, Zeroizing};

#[cfg(target_os = "macos")]
use defguard_wireguard_rs::Userspace;

#[derive(Clone)]
pub struct WireGuardConfig {
    private_key: SensitiveString,
    pub public_key: String,
    pub listen_port: u32,
    pub interface_ipv4: String,
    pub interface_ipv6: Option<String>,
    pub interface_name: String,
}

impl WireGuardConfig {
    fn new(
        private_key: SensitiveString,
        public_key: String,
        listen_port: u32,
        interface_ipv4: String,
        interface_ipv6: Option<String>,
        interface_name: String,
    ) -> Self {
        Self {
            private_key,
            public_key,
            listen_port,
            interface_ipv4,
            interface_ipv6,
            interface_name,
        }
    }

    fn private_key(&self) -> &SensitiveString {
        &self.private_key
    }

    fn clear_private_key(&mut self) {
        self.private_key.clear();
    }
}

impl fmt::Debug for WireGuardConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireGuardConfig")
            .field("public_key", &self.public_key)
            .field("listen_port", &self.listen_port)
            .field("interface_ipv4", &self.interface_ipv4)
            .field("interface_ipv6", &self.interface_ipv6)
            .field("interface_name", &self.interface_name)
            .finish()
    }
}

#[derive(Clone)]
struct SensitiveString(Zeroizing<String>);

impl SensitiveString {
    fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    fn as_str(&self) -> &str {
        self.0.as_ref()
    }

    fn clear(&mut self) {
        self.0.zeroize();
        self.0 = Zeroizing::new(String::new());
    }

    fn sensitive(&self) -> Sensitive<'_> {
        Sensitive(self.as_str())
    }
}

impl fmt::Debug for SensitiveString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl fmt::Display for SensitiveString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

struct Sensitive<'a>(&'a str);

impl<'a> fmt::Debug for Sensitive<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = self.0;
        write!(f, "[REDACTED]")
    }
}

impl<'a> fmt::Display for Sensitive<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = self.0;
        write!(f, "[REDACTED]")
    }
}

struct ConfigGuard<'a> {
    guard: std::sync::MutexGuard<'a, Option<WireGuardConfig>>,
}

impl<'a> ConfigGuard<'a> {
    fn new(guard: std::sync::MutexGuard<'a, Option<WireGuardConfig>>) -> Self {
        Self { guard }
    }

    fn insert(&mut self, config: WireGuardConfig) -> &mut WireGuardConfig {
        *self.guard = Some(config);
        self.guard.as_mut().expect("config must be present")
    }
}

impl<'a> Drop for ConfigGuard<'a> {
    fn drop(&mut self) {
        if let Some(config) = self.guard.as_mut() {
            config.clear_private_key();
        }
    }
}

#[derive(Debug, Clone)]
pub struct PeerSnapshot {
    pub public_key: String,
    pub last_handshake: Option<SystemTime>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub persistent_keepalive_interval: Option<u16>,
}

pub struct WireGuardManager {
    config: Arc<Mutex<Option<WireGuardConfig>>>,
    #[cfg(not(target_os = "macos"))]
    wg_api: Arc<Mutex<Option<WGApi<Kernel>>>>,
    #[cfg(target_os = "macos")]
    wg_api: Arc<Mutex<Option<WGApi<Userspace>>>>,
    interface_configured: Arc<Mutex<bool>>,
    forwarding_state: Arc<Mutex<ForwardingState>>,
}

impl WireGuardManager {
    pub fn new() -> Self {
        Self {
            config: Arc::new(Mutex::new(None)),
            wg_api: Arc::new(Mutex::new(None)),
            interface_configured: Arc::new(Mutex::new(false)),
            forwarding_state: Arc::new(Mutex::new(ForwardingState::default())),
        }
    }

    /// Configure WireGuard with keys received from control plane
    pub fn configure_wireguard(
        &self,
        private_key: String,
        public_key: String,
        listen_port: u32,
        interface_ipv4: String,
        interface_ipv6: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!("🔧 Configuring WireGuard interface...");

        // Determine interface name based on OS
        let interface_name = self.get_interface_name();

        let public_key_for_log = public_key.clone();
        let config = WireGuardConfig::new(
            SensitiveString::new(private_key),
            public_key,
            listen_port,
            interface_ipv4.clone(),
            interface_ipv6.clone(),
            interface_name.clone(),
        );

        let mut config_guard = ConfigGuard::new(self.config.lock().unwrap());
        let config_ref = config_guard.insert(config);
        debug!(
            "WireGuard private key staged: {}",
            config_ref.private_key().sensitive()
        );

        // Create WireGuard API instance
        #[cfg(not(target_os = "macos"))]
        let wg_api = WGApi::<Kernel>::new(interface_name.clone())?;
        #[cfg(target_os = "macos")]
        let wg_api = WGApi::<Userspace>::new(interface_name.clone())?;

        // Store API instance
        {
            let mut api_guard = self.wg_api.lock().unwrap();
            *api_guard = Some(wg_api);
        }

        // Create the interface
        self.create_interface()?;

        // Configure the interface with our keys
        self.apply_configuration(config_ref)?;

        debug!("WireGuard private key cleared after configuration");

        drop(config_guard);

        if let Err(err) = self.configure_forwarding(&interface_name) {
            self.cleanup_forwarding();
            self.remove_interface_best_effort();
            {
                let mut config_guard = self.config.lock().unwrap();
                *config_guard = None;
            }
            return Err(err);
        }

        // Mark as configured
        {
            let mut configured = self.interface_configured.lock().unwrap();
            *configured = true;
        }

        info!("✅ WireGuard interface configured successfully!");
        info!("  Interface: {}", interface_name);
        info!("  IPv4: {}", interface_ipv4);
        if let Some(ipv6) = interface_ipv6 {
            info!("  IPv6: {}", ipv6);
        }
        info!("  Listen Port: {}", listen_port);
        info!("  Public Key: {}", public_key_for_log);

        Ok(())
    }

    pub fn configure_from_registration(
        &self,
        registration: &AgentRegistration,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!("🎉 Agent registered successfully!");
        info!("  Status: {}", registration.status);
        info!("  Control Plane Public Key: {}", registration.wg_public_key);
        info!("  WireGuard Listen Port: {}", registration.wg_listen_port);

        match self.configure_wireguard(
            registration.wg_private_key.clone(),
            registration.wg_public_key.clone(),
            registration.wg_listen_port,
            {
                let ipv4 = registration.wg_interface_ipv4.trim();
                if ipv4.is_empty() {
                    return Err("Control plane did not provide IPv4 interface address".into());
                }
                ipv4.to_string()
            },
            if registration.wg_interface_ipv6.trim().is_empty() {
                None
            } else {
                Some(registration.wg_interface_ipv6.clone())
            },
        ) {
            Ok(_) => {
                if let Ok(status) = self.get_interface_status() {
                    info!("📊 WireGuard Interface Status:\n{}", status);
                }
                Ok(())
            }
            Err(err) => {
                error!(?err, "❌ Failed to configure WireGuard from registration");
                error!("The agent will continue running but VPN functionality will be disabled.");
                Err(err)
            }
        }
    }

    pub fn add_peer_from_request(
        &self,
        request: &PeerAdd,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let allowed_ips = if !request.allowed_ips.is_empty() {
            request.allowed_ips.clone()
        } else {
            vec!["0.0.0.0/0".to_string()]
        };

        self.add_peer(&request.public_key, allowed_ips, None)
            .map(|_| {
                info!(
                    "✅ Peer added (agent: {}, public_key: {}, lease_version: {})",
                    request.agent_id, request.public_key, request.lease_version
                );
            })
    }

    pub fn remove_peer_from_request(
        &self,
        request: &PeerRemove,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.remove_peer(&request.public_key).map(|_| {
            info!(
                "✅ Peer removed (agent: {}, public_key: {})",
                request.agent_id, request.public_key
            );
        })
    }

    fn get_interface_name(&self) -> String {
        if cfg!(target_os = "linux") || cfg!(target_os = "freebsd") {
            "wg0".to_string()
        } else {
            "utun3".to_string()
        }
    }

    fn create_interface(&self) -> Result<(), Box<dyn std::error::Error>> {
        let api_guard = self.wg_api.lock().unwrap();
        if let Some(ref wg_api) = *api_guard {
            info!("Creating WireGuard interface...");
            wg_api.create_interface()?;

            // Read and display initial interface status
            let host = wg_api.read_interface_data()?;
            debug!("WireGuard interface created: {:#?}", host);
        } else {
            return Err("WireGuard API not initialized".into());
        }
        Ok(())
    }

    pub fn peer_snapshots(&self) -> Result<Vec<PeerSnapshot>, Box<dyn std::error::Error>> {
        if !self.is_configured() {
            return Ok(Vec::new());
        }

        let api_guard = self.wg_api.lock().unwrap();
        if let Some(ref wg_api) = *api_guard {
            let host = wg_api.read_interface_data()?;
            let snapshots = host
                .peers
                .into_iter()
                .map(|(key, peer)| PeerSnapshot {
                    public_key: key.to_lower_hex(),
                    last_handshake: peer.last_handshake,
                    tx_bytes: peer.tx_bytes,
                    rx_bytes: peer.rx_bytes,
                    persistent_keepalive_interval: peer.persistent_keepalive_interval,
                })
                .collect();
            Ok(snapshots)
        } else {
            Err("WireGuard API not initialized".into())
        }
    }

    fn apply_configuration(
        &self,
        config: &mut WireGuardConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let api_guard = self.wg_api.lock().unwrap();
        if let Some(ref wg_api) = *api_guard {
            info!("Applying WireGuard configuration...");

            let mut interface_config = InterfaceConfiguration {
                name: config.interface_name.clone(),
                prvkey: config.private_key().as_str().to_owned(),
                addresses: {
                    let mut addrs = Vec::new();
                    addrs.push(IpAddrMask::from_str(&config.interface_ipv4)?);
                    if let Some(ref ipv6) = config.interface_ipv6 {
                        addrs.push(IpAddrMask::from_str(ipv6)?);
                    }
                    addrs
                },
                port: config.listen_port,
                peers: vec![], // No initial peers - they will be added when other agents connect
                mtu: Some(1420), // Standard WireGuard MTU
            };

            debug!("Interface configuration: {:#?}", interface_config);

            // Apply configuration
            #[cfg(not(windows))]
            let configure_result = wg_api.configure_interface(&interface_config);
            #[cfg(windows)]
            let configure_result = wg_api.configure_interface(&interface_config, &[]);

            interface_config.prvkey.zeroize();
            configure_result?;

            // Private key no longer needed after successful configuration.
            config.clear_private_key();

            // Read and display final interface status
            let host = wg_api.read_interface_data()?;
            debug!("WireGuard interface configured: {:#?}", host);
        } else {
            return Err("WireGuard API not initialized".into());
        }
        Ok(())
    }

    /// Add a peer to the WireGuard interface
    pub fn add_peer(
        &self,
        peer_public_key: &str,
        allowed_ips: Vec<String>,
        endpoint: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !self.is_configured() {
            return Err("WireGuard interface not configured".into());
        }

        let api_guard = self.wg_api.lock().unwrap();
        if let Some(ref wg_api) = *api_guard {
            // Parse the peer public key
            let peer_key_bytes =
                base64::engine::general_purpose::STANDARD.decode(peer_public_key)?;
            if peer_key_bytes.len() != 32 {
                return Err("Invalid public key length".into());
            }
            let peer_key: Key = peer_key_bytes.as_slice().try_into()?;

            let mut peer = Peer::new(peer_key);

            // Add allowed IPs
            for ip_str in allowed_ips {
                let addr = IpAddrMask::from_str(&ip_str)?;
                peer.allowed_ips.push(addr);
            }

            // Set endpoint if provided
            if let Some(endpoint_str) = endpoint {
                peer.endpoint = Some(endpoint_str.parse()?);
            }

            // Add the peer
            wg_api.configure_peer(&peer)?;
        } else {
            return Err("WireGuard API not initialized".into());
        }
        Ok(())
    }

    /// Remove a peer from the WireGuard interface
    pub fn remove_peer(&self, peer_public_key: &str) -> Result<(), Box<dyn std::error::Error>> {
        if !self.is_configured() {
            return Err("WireGuard interface not configured".into());
        }

        let api_guard = self.wg_api.lock().unwrap();
        if let Some(ref wg_api) = *api_guard {
            // Parse the peer public key
            let peer_key_bytes =
                base64::engine::general_purpose::STANDARD.decode(peer_public_key)?;
            if peer_key_bytes.len() != 32 {
                return Err("Invalid public key length".into());
            }
            let peer_key: Key = peer_key_bytes.as_slice().try_into()?;

            // Remove the peer
            wg_api.remove_peer(&peer_key)?;
        } else {
            return Err("WireGuard API not initialized".into());
        }
        Ok(())
    }

    /// Get current interface status
    pub fn get_interface_status(&self) -> Result<String, Box<dyn std::error::Error>> {
        if !self.is_configured() {
            return Err("WireGuard interface not configured".into());
        }

        let api_guard = self.wg_api.lock().unwrap();
        if let Some(ref wg_api) = *api_guard {
            let host = wg_api.read_interface_data()?;
            Ok(format!("{host:#?}"))
        } else {
            Err("WireGuard API not initialized".into())
        }
    }

    /// Cleanup - remove the interface
    pub fn cleanup(&self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.is_configured() {
            return Ok(()); // Nothing to cleanup
        }

        let api_guard = self.wg_api.lock().unwrap();
        if let Some(ref wg_api) = *api_guard {
            info!("🧹 Cleaning up WireGuard interface...");
            wg_api.remove_interface()?;
            info!("✅ WireGuard interface removed");
        }

        self.cleanup_forwarding();

        // Reset state
        {
            let mut configured = self.interface_configured.lock().unwrap();
            *configured = false;
        }
        {
            let mut config_guard = self.config.lock().unwrap();
            *config_guard = None;
        }

        Ok(())
    }

    pub fn is_configured(&self) -> bool {
        let configured = self.interface_configured.lock().unwrap();
        *configured
    }

    pub fn get_config(&self) -> Option<WireGuardConfig> {
        let config_guard = self.config.lock().unwrap();
        config_guard.clone()
    }

    fn configure_forwarding(&self, wg_iface: &str) -> Result<(), Box<dyn std::error::Error>> {
        let cidr_v4 = firewall::wireguard_cidr_from_env();
        let cidr_v6 = firewall::wireguard_ipv6_cidr_from_env();
        let egress_override = std::env::var("VPN9_EGRESS_IFACE").ok();

        match firewall::ensure_forwarding(
            wg_iface,
            cidr_v4.as_str(),
            cidr_v6.as_deref(),
            egress_override.as_deref(),
        ) {
            Ok(state) => {
                let mut guard = self.forwarding_state.lock().unwrap();
                *guard = state;
                info!(
                    interface = wg_iface,
                    ipv4_cidr = %cidr_v4,
                    ipv6_cidr = cidr_v6.as_deref().unwrap_or("disabled"),
                    egress = egress_override.as_deref().unwrap_or("auto"),
                    "nftables forwarding configured"
                );
                Ok(())
            }
            Err(err) => {
                error!(?err, "Failed to configure nftables forwarding rules");
                Err(Box::new(err))
            }
        }
    }

    fn cleanup_forwarding(&self) {
        let mut guard = self.forwarding_state.lock().unwrap();
        if let Err(err) = firewall::teardown_forwarding(&mut guard) {
            warn!(?err, "Failed to teardown nftables rules during cleanup");
        }
    }

    fn remove_interface_best_effort(&self) {
        let api_guard = self.wg_api.lock().unwrap();
        if let Some(ref wg_api) = *api_guard {
            if let Err(err) = wg_api.remove_interface() {
                warn!(
                    ?err,
                    "Failed to remove WireGuard interface after forwarding failure"
                );
            } else {
                info!("WireGuard interface removed after forwarding failure");
            }
        }

        {
            let mut configured = self.interface_configured.lock().unwrap();
            *configured = false;
        }
    }
}

impl Drop for WireGuardManager {
    fn drop(&mut self) {
        // Attempt cleanup on drop
        if let Err(e) = self.cleanup() {
            warn!("Failed to cleanup WireGuard interface: {}", e);
        }
    }
}

impl Default for WireGuardManager {
    fn default() -> Self {
        Self::new()
    }
}

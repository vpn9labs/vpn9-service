use std::str::FromStr;
use std::sync::{Arc, Mutex};

use base64::Engine;
use defguard_wireguard_rs::{
    InterfaceConfiguration, Kernel, WGApi, WireguardInterfaceApi, host::Peer, key::Key,
    net::IpAddrMask,
};
use tracing::{debug, info, warn};
use x25519_dalek::{PublicKey, StaticSecret};

#[cfg(target_os = "macos")]
use defguard_wireguard_rs::Userspace;

#[derive(Debug, Clone)]
pub struct WireGuardConfig {
    pub private_key: String,
    pub public_key: String,
    pub listen_port: u32,
    pub interface_address: String,
    pub interface_name: String,
}

pub struct WireGuardManager {
    config: Arc<Mutex<Option<WireGuardConfig>>>,
    #[cfg(not(target_os = "macos"))]
    wg_api: Arc<Mutex<Option<WGApi<Kernel>>>>,
    #[cfg(target_os = "macos")]
    wg_api: Arc<Mutex<Option<WGApi<Userspace>>>>,
    interface_configured: Arc<Mutex<bool>>,
}

impl WireGuardManager {
    pub fn new() -> Self {
        Self {
            config: Arc::new(Mutex::new(None)),
            wg_api: Arc::new(Mutex::new(None)),
            interface_configured: Arc::new(Mutex::new(false)),
        }
    }

    /// Generate a new WireGuard key pair
    pub fn generate_keypair() -> Result<(String, String), Box<dyn std::error::Error>> {
        let private_secret = StaticSecret::random();
        let public_key = PublicKey::from(&private_secret);

        let private_key_bytes: [u8; 32] = private_secret.to_bytes();
        let public_key_bytes: [u8; 32] = public_key.to_bytes();

        let private_key = base64::engine::general_purpose::STANDARD.encode(private_key_bytes);
        let public_key = base64::engine::general_purpose::STANDARD.encode(public_key_bytes);

        Ok((private_key, public_key))
    }

    /// Configure WireGuard with keys received from control plane
    pub fn configure_wireguard(
        &self,
        private_key: String,
        public_key: String,
        listen_port: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!("🔧 Configuring WireGuard interface...");
        debug!("Private key (base64): {}", &private_key);
        debug!("Public key (base64): {}", &public_key);

        // Determine interface name based on OS
        let interface_name = self.get_interface_name();

        // Assign IP address for this agent (in production, this should come from control plane)
        let interface_address = self.generate_interface_address()?;

        let config = WireGuardConfig {
            private_key: private_key.clone(),
            public_key: public_key.clone(),
            listen_port,
            interface_address: interface_address.clone(),
            interface_name: interface_name.clone(),
        };

        // Store configuration
        {
            let mut config_guard = self.config.lock().unwrap();
            *config_guard = Some(config.clone());
        }

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
        self.apply_configuration(&config)?;

        // Mark as configured
        {
            let mut configured = self.interface_configured.lock().unwrap();
            *configured = true;
        }

        info!("✅ WireGuard interface configured successfully!");
        info!("  Interface: {}", interface_name);
        info!("  Address: {}", interface_address);
        info!("  Listen Port: {}", listen_port);
        info!("  Public Key: {}", public_key);

        Ok(())
    }

    fn get_interface_name(&self) -> String {
        if cfg!(target_os = "linux") || cfg!(target_os = "freebsd") {
            "wg0".to_string()
        } else {
            "utun3".to_string()
        }
    }

    /// Generate IP address for this agent interface
    /// In production, this should be assigned by the control plane
    fn generate_interface_address(&self) -> Result<String, Box<dyn std::error::Error>> {
        // For now, use a simple approach - in production, control plane should assign this
        let base_ip = "10.8.0";
        let host_part = 2; // This should be dynamically assigned
        Ok(format!("{base_ip}.{host_part}"))
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

    fn apply_configuration(
        &self,
        config: &WireGuardConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let api_guard = self.wg_api.lock().unwrap();
        if let Some(ref wg_api) = *api_guard {
            info!("Applying WireGuard configuration...");

            // Parse the interface address with CIDR notation (switched to /8)
            let interface_addr_with_cidr = format!("{}/8", config.interface_address);
            let interface_addr = IpAddrMask::from_str(&interface_addr_with_cidr)?;

            let interface_config = InterfaceConfiguration {
                name: config.interface_name.clone(),
                prvkey: config.private_key.clone(),
                addresses: vec![interface_addr],
                port: config.listen_port,
                peers: vec![], // No initial peers - they will be added when other agents connect
                mtu: Some(1420), // Standard WireGuard MTU
            };

            debug!("Interface configuration: {:#?}", interface_config);

            // Apply configuration
            #[cfg(not(windows))]
            wg_api.configure_interface(&interface_config)?;
            #[cfg(windows)]
            wg_api.configure_interface(&interface_config, &[])?;

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
            info!("Adding peer: {}", peer_public_key);

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

            info!("✅ Peer added successfully: {}", peer_public_key);
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
            info!("Removing peer: {}", peer_public_key);

            // Parse the peer public key
            let peer_key_bytes =
                base64::engine::general_purpose::STANDARD.decode(peer_public_key)?;
            if peer_key_bytes.len() != 32 {
                return Err("Invalid public key length".into());
            }
            let peer_key: Key = peer_key_bytes.as_slice().try_into()?;

            // Remove the peer
            wg_api.remove_peer(&peer_key)?;

            info!("✅ Peer removed successfully: {}", peer_public_key);
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

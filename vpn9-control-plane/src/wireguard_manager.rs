use base64::Engine;
use defguard_wireguard_rs::{
    InterfaceConfiguration, Kernel, WGApi, WireguardInterfaceApi, host::Peer, key::Key,
    net::IpAddrMask,
};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;
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
    next_peer_ip: Arc<Mutex<u32>>,
}

impl WireGuardManager {
    pub fn new() -> Self {
        Self {
            config: Arc::new(Mutex::new(None)),
            wg_api: Arc::new(Mutex::new(None)),
            interface_configured: Arc::new(Mutex::new(false)),
            next_peer_ip: Arc::new(Mutex::new(2)),
        }
    }

    pub fn generate_keypair() -> Result<(String, String), Box<dyn std::error::Error>> {
        let private_secret = StaticSecret::random();
        let public_key = PublicKey::from(&private_secret);

        let private_key_bytes: [u8; 32] = private_secret.to_bytes();
        let public_key_bytes: [u8; 32] = public_key.to_bytes();

        let private_key = base64::engine::general_purpose::STANDARD.encode(private_key_bytes);
        let public_key = base64::engine::general_purpose::STANDARD.encode(public_key_bytes);

        Ok((private_key, public_key))
    }

    pub async fn configure(
        &self,
        config: WireGuardConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        *self.config.lock().await = Some(config.clone());

        #[cfg(not(target_os = "macos"))]
        let wg_api = WGApi::<Kernel>::new(config.interface_name.clone())?;

        #[cfg(target_os = "macos")]
        let wg_api = WGApi::<Userspace>::new(config.interface_name.clone())?;

        let interface_config = InterfaceConfiguration {
            name: config.interface_name.clone(),
            prvkey: config.private_key.clone(),
            addresses: vec![IpAddrMask::from_str(&config.interface_address)?],
            port: config.listen_port,
            mtu: Some(1420),
            peers: vec![],
        };

        wg_api.configure_interface(&interface_config)?;

        *self.wg_api.lock().await = Some(wg_api);
        *self.interface_configured.lock().await = true;

        info!("WireGuard interface {} configured", config.interface_name);
        Ok(())
    }

    pub async fn add_peer(&self, peer_public_key: &str) -> Result<(), Box<dyn std::error::Error>> {
        let wg_api_lock = self.wg_api.lock().await;
        let wg_api = wg_api_lock
            .as_ref()
            .ok_or("WireGuard interface not configured")?;

        let mut next_ip = self.next_peer_ip.lock().await;
        let peer_ip = format!("10.0.0.{}/32", *next_ip);
        *next_ip += 1;

        let peer_key = Key::from_str(peer_public_key)?;

        let peer = Peer {
            public_key: peer_key,
            preshared_key: None,
            protocol_version: None,
            endpoint: None,
            persistent_keepalive_interval: Some(25),
            allowed_ips: vec![IpAddrMask::from_str(&peer_ip)?],
            rx_bytes: 0,
            tx_bytes: 0,
            last_handshake: None,
        };

        wg_api.configure_peer(&peer)?;

        info!(
            "Added WireGuard peer with public key: {} and IP: {}",
            peer_public_key, peer_ip
        );
        Ok(())
    }

    pub async fn remove_peer(
        &self,
        peer_public_key: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let wg_api_lock = self.wg_api.lock().await;
        let wg_api = wg_api_lock
            .as_ref()
            .ok_or("WireGuard interface not configured")?;

        let peer_key = Key::from_str(peer_public_key)?;
        wg_api.remove_peer(&peer_key)?;

        info!(
            "Removed WireGuard peer with public key: {}",
            peer_public_key
        );
        Ok(())
    }

    pub async fn list_peers(&self) -> Result<Vec<Peer>, Box<dyn std::error::Error>> {
        let wg_api_lock = self.wg_api.lock().await;
        let wg_api = wg_api_lock
            .as_ref()
            .ok_or("WireGuard interface not configured")?;

        let device = wg_api.read_interface_data()?;
        Ok(device.peers.into_values().collect())
    }
}

impl Default for WireGuardManager {
    fn default() -> Self {
        Self::new()
    }
}

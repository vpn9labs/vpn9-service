use std::net::SocketAddr;
use tracing::{info, warn};

/// Configuration for the VPN9 Control Plane server
#[derive(Debug, Clone)]
pub struct Config {
    /// The address and port to bind the server to
    pub bind_address: SocketAddr,
    /// Current version of the control plane
    pub current_version: String,
    /// Path to the directory containing update files
    pub update_path: String,
    /// Path to the TLS certificate file
    pub tls_cert_path: String,
    /// Path to the TLS private key file
    pub tls_key_path: String,
    /// Domain name for TLS verification
    pub tls_domain: String,
    /// WireGuard interface name
    pub wireguard_interface: String,
    /// WireGuard private key
    pub wireguard_private_key: String,
    /// WireGuard listen port
    pub wireguard_listen_port: u32,
    /// WireGuard interface address
    pub wireguard_interface_address: String,
    /// Redis URL for device registry
    pub redis_url: String,
    /// Poll interval in seconds for registry refresh
    pub registry_poll_interval_secs: u64,
}

impl Config {
    /// Load configuration from environment variables with sensible defaults
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let bind_address = std::env::var("VPN9_BIND_ADDRESS")
            .unwrap_or_else(|_| "0.0.0.0:50051".to_string())
            .parse()?;

        let current_version = std::env::var("VPN9_CONTROL_PLANE_VERSION").unwrap_or_else(|_| {
            warn!("VPN9_CONTROL_PLANE_VERSION not set, using default: 1.0.0");
            "1.0.0".to_string()
        });

        let update_path = std::env::var("VPN9_UPDATE_PATH").unwrap_or_else(|_| {
            info!("VPN9_UPDATE_PATH not set, using default: ./updates/");
            "./updates/".to_string()
        });

        let tls_cert_path = std::env::var("VPN9_TLS_CERT_PATH")
            .unwrap_or_else(|_| "./certs/server.crt".to_string());

        let tls_key_path =
            std::env::var("VPN9_TLS_KEY_PATH").unwrap_or_else(|_| "./certs/server.key".to_string());

        let tls_domain =
            std::env::var("VPN9_TLS_DOMAIN").unwrap_or_else(|_| "vpn9-control-plane".to_string());

        let wireguard_interface =
            std::env::var("VPN9_WIREGUARD_INTERFACE").unwrap_or_else(|_| "wg0".to_string());

        let wireguard_private_key = std::env::var("VPN9_WIREGUARD_PRIVATE_KEY")
            .ok()
            .or_else(|| {
                // Generate a new key if not provided
                crate::wireguard_manager::WireGuardManager::generate_keypair()
                    .ok()
                    .map(|(priv_key, _)| priv_key)
            })
            .unwrap_or_else(|| {
                warn!("VPN9_WIREGUARD_PRIVATE_KEY not set, generating new key");
                "".to_string()
            });

        let wireguard_listen_port: u32 = std::env::var("VPN9_WIREGUARD_LISTEN_PORT")
            .unwrap_or_else(|_| "51820".to_string())
            .parse()?;

        let wireguard_interface_address = std::env::var("VPN9_WIREGUARD_INTERFACE_ADDRESS")
            .unwrap_or_else(|_| "10.0.0.1/24".to_string());

        let redis_url = std::env::var("KREDIS_URL")
            .or_else(|_| std::env::var("REDIS_URL"))
            .unwrap_or_else(|_| "redis://127.0.0.1:6379/1".to_string());

        let registry_poll_interval_secs: u64 = std::env::var("VPN9_REGISTRY_POLL_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);

        info!(
            bind_address = %bind_address,
            current_version = %current_version,
            update_path = %update_path,
            tls_cert_path = %tls_cert_path,
            tls_key_path = %tls_key_path,
            tls_domain = %tls_domain,
            wireguard_interface = %wireguard_interface,
            wireguard_listen_port = %wireguard_listen_port,
            wireguard_interface_address = %wireguard_interface_address,
            redis_url = %redis_url,
            registry_poll_interval_secs = %registry_poll_interval_secs,
            "Configuration loaded from environment"
        );

        Ok(Config {
            bind_address,
            current_version,
            update_path,
            tls_cert_path,
            tls_key_path,
            tls_domain,
            wireguard_interface,
            wireguard_private_key,
            wireguard_listen_port,
            wireguard_interface_address,
            redis_url,
            registry_poll_interval_secs,
        })
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Check if TLS files exist
        if !std::path::Path::new(&self.tls_cert_path).exists() {
            return Err(format!("TLS certificate file not found: {}", self.tls_cert_path).into());
        }

        if !std::path::Path::new(&self.tls_key_path).exists() {
            return Err(format!("TLS key file not found: {}", self.tls_key_path).into());
        }

        // Create update directory if it doesn't exist
        if !std::path::Path::new(&self.update_path).exists() {
            std::fs::create_dir_all(&self.update_path).map_err(|e| {
                format!(
                    "Failed to create update directory {}: {}",
                    self.update_path, e
                )
            })?;
            info!(update_path = %self.update_path, "Created update directory");
        }

        info!("Configuration validation completed successfully");
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            bind_address: "0.0.0.0:50051".parse().unwrap(),
            current_version: "1.0.0".to_string(),
            update_path: "./updates/".to_string(),
            tls_cert_path: "./certs/server.crt".to_string(),
            tls_key_path: "./certs/server.key".to_string(),
            tls_domain: "vpn9-control-plane".to_string(),
            wireguard_interface: "wg0".to_string(),
            wireguard_private_key: "".to_string(),
            wireguard_listen_port: 51820,
            wireguard_interface_address: "10.0.0.1/24".to_string(),
            redis_url: "redis://127.0.0.1:6379/1".to_string(),
            registry_poll_interval_secs: 10,
        }
    }
}

use std::net::SocketAddr;
use tracing::{info, warn};

/// Configuration for the VPN9 Control Plane server
#[derive(Debug, Clone)]
pub struct Config {
    /// The address and port to bind the server to
    pub bind_address: SocketAddr,
    /// Current version of the control plane
    pub current_version: String,
    /// Path to the TLS certificate file
    pub tls_cert_path: String,
    /// Path to the TLS private key file
    pub tls_key_path: String,
    /// Domain name for TLS verification
    pub tls_domain: String,
    // WireGuard settings are managed by agents; kept for compatibility only
    /// Redis URL for device registry
    pub redis_url: String,
    /// Poll interval in seconds for registry refresh
    pub registry_poll_interval_secs: u64,
    /// Lease TTL for device<->relay assignment tokens
    pub lease_ttl_secs: u64,
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

        let tls_cert_path = std::env::var("VPN9_TLS_CERT_PATH")
            .unwrap_or_else(|_| "./certs/server.crt".to_string());

        let tls_key_path =
            std::env::var("VPN9_TLS_KEY_PATH").unwrap_or_else(|_| "./certs/server.key".to_string());

        let tls_domain =
            std::env::var("VPN9_TLS_DOMAIN").unwrap_or_else(|_| "vpn9-control-plane".to_string());

        // WireGuard settings are managed entirely by agents; no control-plane reads

        let redis_url = std::env::var("KREDIS_URL")
            .or_else(|_| std::env::var("REDIS_URL"))
            .unwrap_or_else(|_| "redis://127.0.0.1:6379/1".to_string());

        let registry_poll_interval_secs: u64 = std::env::var("VPN9_REGISTRY_POLL_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);

        let lease_ttl_secs: u64 = std::env::var("VPN9_LEASE_TTL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(180);

        info!(
            bind_address = %bind_address,
            current_version = %current_version,
            tls_cert_path = %tls_cert_path,
            tls_key_path = %tls_key_path,
            tls_domain = %tls_domain,
            // WireGuard settings removed from control plane; managed by agents
            redis_url = %redis_url,
            registry_poll_interval_secs = %registry_poll_interval_secs,
            lease_ttl_secs = lease_ttl_secs,
            "Configuration loaded from environment"
        );

        Ok(Config {
            bind_address,
            current_version,
            tls_cert_path,
            tls_key_path,
            tls_domain,
            redis_url,
            registry_poll_interval_secs,
            lease_ttl_secs,
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

        info!("Configuration validation completed successfully");
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            bind_address: "0.0.0.0:50051".parse().unwrap(),
            current_version: "1.0.0".to_string(),
            tls_cert_path: "./certs/server.crt".to_string(),
            tls_key_path: "./certs/server.key".to_string(),
            tls_domain: "vpn9-control-plane".to_string(),
            redis_url: "redis://127.0.0.1:6379/1".to_string(),
            registry_poll_interval_secs: 10,
            lease_ttl_secs: 180,
        }
    }
}

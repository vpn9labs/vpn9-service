use std::fs;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tracing::{error, info};

use vpn9_core::control_plane::control_plane_server::ControlPlaneServer;

use crate::config::Config;
use crate::device_registry::DeviceRegistry;
use crate::keystore::StrongBoxKeystore;
use crate::lease_manager::LeaseManager;
use crate::service::VPN9ControlPlane;

/// TLS server configuration and startup logic
#[derive(Debug)]
pub struct TlsServer {
    config: Config,
}

impl TlsServer {
    /// Create a new TLS server instance
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Initialize and start the TLS server
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!(
            bind_address = %self.config.bind_address,
            "Starting VPN9 Control Plane server with TLS"
        );

        // Load TLS certificate and key
        let cert = fs::read(&self.config.tls_cert_path).map_err(|e| {
            format!(
                "Failed to read certificate file {}: {}",
                self.config.tls_cert_path, e
            )
        })?;

        let key = fs::read(&self.config.tls_key_path).map_err(|e| {
            format!(
                "Failed to read private key file {}: {}",
                self.config.tls_key_path, e
            )
        })?;

        let identity = Identity::from_pem(cert, key);
        let tls_config = ServerTlsConfig::new().identity(identity);

        info!(
            cert_path = %self.config.tls_cert_path,
            key_path = %self.config.tls_key_path,
            "TLS certificate and private key loaded successfully"
        );

        // Initialize device registry (Redis) and start background polling
        let registry =
            std::sync::Arc::new(DeviceRegistry::new(&self.config.redis_url).await.map_err(
                |e| {
                    format!(
                        "Failed to connect to Redis at {}: {}",
                        self.config.redis_url, e
                    )
                },
            )?);
        registry
            .full_sync()
            .await
            .map_err(|e| format!("Failed initial device registry sync: {e}"))?;
        registry
            .clone()
            .start_polling(self.config.registry_poll_interval_secs);

        // Create the control plane service with registry
        let keystore = std::sync::Arc::new(
            StrongBoxKeystore::from_env(&self.config.redis_url)
                .await
                .map_err(|e| format!("Failed to initialize keystore: {e}"))?,
        );

        // Initialize lease manager for device session tokens
        let lease_manager = std::sync::Arc::new(
            LeaseManager::new(
                &self.config.redis_url,
                std::time::Duration::from_secs(self.config.lease_ttl_secs),
            )
            .await
            .map_err(|e| format!("Failed to initialize lease manager: {e}"))?,
        );

        // Create the control plane service with registry + keystore + leases
        let control_plane = VPN9ControlPlane::new_with_registry_and_keystore(
            self.config.clone(),
            registry,
            keystore,
            lease_manager,
        );

        info!("VPN9 Control Plane server starting...");
        let server = match Server::builder().tls_config(tls_config) {
            Ok(mut server_builder) => {
                server_builder.add_service(ControlPlaneServer::new(control_plane))
            }
            Err(e) => {
                error!(error = %e, "Failed to configure TLS for server");
                return Err(e.into());
            }
        };

        info!(
            bind_address = %self.config.bind_address,
            "Server ready to listen on address"
        );
        info!("VPN9 Control Plane server is now listening for gRPC connections");

        match server.serve(self.config.bind_address).await {
            Ok(_) => {
                info!("Server shut down gracefully");
            }
            Err(e) => {
                error!(
                    error = %e,
                    bind_address = %self.config.bind_address,
                    "Server failed to start or encountered error"
                );
                return Err(e.into());
            }
        }

        info!("VPN9 Control Plane server stopped");
        Ok(())
    }

    /// Initialize cryptographic providers
    pub fn init_crypto() -> Result<(), Box<dyn std::error::Error>> {
        rustls::crypto::ring::default_provider()
            .install_default()
            .map_err(|_| "Failed to install default crypto provider")?;
        info!("Cryptographic providers initialized");
        Ok(())
    }

    /// Initialize tracing/logging
    pub fn init_logging() {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "vpn9_control_plane=info,tonic=warn".into()),
            )
            .init();
        info!("Logging initialized");
    }
}

/// Builder pattern for creating and configuring a TLS server
pub struct TlsServerBuilder {
    config: Option<Config>,
}

impl TlsServerBuilder {
    /// Create a new server builder
    pub fn new() -> Self {
        Self { config: None }
    }

    /// Set the configuration for the server
    pub fn with_config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    /// Build the TLS server
    pub fn build(self) -> Result<TlsServer, Box<dyn std::error::Error>> {
        let config = self.config.ok_or("Configuration is required")?;
        config.validate()?;
        Ok(TlsServer::new(config))
    }
}

impl Default for TlsServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_server_creation() {
        let config = Config::default();
        let server = TlsServer::new(config);
        assert_eq!(server.config.bind_address.port(), 50051);
    }

    #[test]
    fn test_server_builder() {
        let config = Config::default();
        let builder = TlsServerBuilder::new().with_config(config);
        // Note: build() would fail in tests due to missing cert files
        assert!(builder.config.is_some());
    }

    #[test]
    fn test_server_builder_missing_config() {
        let builder = TlsServerBuilder::new();
        let result = builder.build();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Configuration is required")
        );
    }
}

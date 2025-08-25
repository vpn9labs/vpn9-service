use std::sync::Arc;
use tokio::sync::RwLock;
use vpn9_control_plane::{
    Config, TlsServerBuilder,
    rest_server::{RestServer, RestServerConfig},
    server::TlsServer,
    wireguard_manager::{WireGuardConfig, WireGuardManager},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging and crypto providers
    TlsServer::init_logging();
    TlsServer::init_crypto()?;

    // Load configuration from environment
    let config = Config::from_env()?;

    // Initialize WireGuard manager
    let wireguard_manager = Arc::new(RwLock::new(WireGuardManager::new()));

    // Configure WireGuard if private key is provided
    if !config.wireguard_private_key.is_empty() {
        let (_, public_key) = WireGuardManager::generate_keypair()
            .unwrap_or_else(|_| (config.wireguard_private_key.clone(), String::new()));

        let wg_config = WireGuardConfig {
            private_key: config.wireguard_private_key.clone(),
            public_key,
            listen_port: config.wireguard_listen_port,
            interface_address: config.wireguard_interface_address.clone(),
            interface_name: config.wireguard_interface.clone(),
        };

        wireguard_manager.write().await.configure(wg_config).await?;
    }

    // Create REST server configuration
    let rest_config = RestServerConfig {
        listen_addr: config.rest_bind_address,
        jwt_public_key_path: config.jwt_public_key_path.clone(),
    };

    // Create REST server
    let rest_server = RestServer::new(rest_config, wireguard_manager)?;

    // Spawn REST server in background
    let rest_handle = tokio::spawn(async move {
        if let Err(e) = rest_server.run().await {
            eprintln!("REST server error: {e}");
        }
    });

    // Create and start the TLS server
    let server = TlsServerBuilder::new().with_config(config).build()?;

    // Run both servers
    tokio::select! {
        result = server.run() => result,
        _ = rest_handle => Ok(()),
    }
}

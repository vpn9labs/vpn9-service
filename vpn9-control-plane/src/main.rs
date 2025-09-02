use vpn9_control_plane::{Config, TlsServerBuilder, server::TlsServer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging and crypto providers
    TlsServer::init_logging();
    TlsServer::init_crypto()?;

    // Load configuration from environment
    let config = Config::from_env()?;

    // Create and start the TLS server
    let server = TlsServerBuilder::new().with_config(config).build()?;

    // Run TLS gRPC server
    server.run().await
}

use std::env;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use vpn9_agent::agent::VPN9Agent;
use vpn9_agent::config::AgentConfig;
use vpn9_agent::version::get_version_info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing subscriber
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("vpn9_agent=info".parse()?))
        .init();

    // Initialize the default crypto provider for rustls
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "Failed to install default crypto provider")?;

    // Support CLI flag for version-only output before we touch configuration
    let args: Vec<String> = env::args().collect();
    let version_info = get_version_info();
    if args.iter().any(|arg| arg == "--version" || arg == "-V") {
        println!("{}", version_info.full_version());
        return Ok(());
    }

    // Load configuration from environment variables
    let config = AgentConfig::load_from_env();

    // Validate configuration
    if let Err(e) = config.validate() {
        error!("Configuration error: {}", e);
        std::process::exit(1);
    }

    info!("🔒 VPN9 Secure Agent Starting...");
    info!("Version Information:");
    info!("  Version: {}", version_info.full_version());
    info!("  Git Branch: {}", version_info.git_branch);
    info!("  Git Hash: {}", version_info.git_hash);
    info!("  Build Time: {}", version_info.build_time);
    info!("Configuration:");
    info!("  Control Plane: {}", config.control_plane_url);
    info!("  Heartbeat Interval: {}s", config.heartbeat_interval_secs);
    info!("Security Features:");
    info!("  ✅ Runtime memory locking");
    info!("  ✅ Core dump prevention");
    info!("  ✅ Environment sanitization");
    info!("  ✅ Secure shutdown handling");

    // Create and start the agent
    let mut agent = VPN9Agent::new(config.control_plane_url.clone())
        .with_heartbeat_interval(config.heartbeat_interval());

    // Start the agent (this will run indefinitely)
    agent.start().await
}

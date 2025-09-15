pub mod agent;
pub mod config;
pub mod runtime_security;
pub mod secure_system_info;
pub mod version;
pub mod wireguard_manager;

pub use agent::VPN9Agent;
pub use config::AgentConfig;
pub use runtime_security::RuntimeSecurity;
pub use secure_system_info::{NetInterface, OsInfo, collect_os_info, secure_zero_memory};
pub use version::{VersionInfo, get_version, get_version_info};
pub use wireguard_manager::{WireGuardConfig, WireGuardManager};

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Connection error: {0}")]
    Connection(#[from] tonic::transport::Error),

    #[error("gRPC error: {0}")]
    Grpc(#[from] tonic::Status),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("System info error: {0}")]
    SystemInfo(String),

    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
}

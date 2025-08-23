//! VPN9 Control Plane
//!
//! A modular control plane implementation for the VPN9 system that provides:
//! - Agent registration and management
//! - Update distribution and management
//! - TLS-secured gRPC communication
//! - WireGuard key management
//!
//! ## Architecture
//!
//! The control plane is organized into several modules:
//! - `config`: Configuration management and environment variable handling
//! - `service`: Main gRPC service implementation
//! - `agent_manager`: Agent registration and subscription handling
//! - `update_manager`: Update distribution and version management
//! - `key_manager`: WireGuard key generation and management
//! - `server`: TLS server setup and startup logic
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use vpn9_control_plane::{Config, TlsServerBuilder};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize logging and crypto
//!     vpn9_control_plane::server::TlsServer::init_logging();
//!     vpn9_control_plane::server::TlsServer::init_crypto()?;
//!
//!     // Load configuration
//!     let config = Config::from_env()?;
//!
//!     // Create and start server
//!     let server = TlsServerBuilder::new()
//!         .with_config(config)
//!         .build()?;
//!
//!     server.run().await
//! }
//! ```

pub mod agent_manager;
pub mod config;
pub mod rest_server;
pub mod server;
pub mod service;
pub mod update_manager;
pub mod wireguard_manager;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use base64::Engine;
use tokio::sync::mpsc;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, Clone)]
pub struct AgentKeys {
    pub private_key: String,
    pub public_key: String,
    pub listen_port: u32,
}

#[derive(Debug, Clone)]
pub struct AgentConnection {
    pub agent_id: String,
    pub keys: AgentKeys,
    pub last_seen: SystemTime,
    pub health_sender: Option<mpsc::UnboundedSender<()>>,
    pub hostname: String,
    pub public_ip: String,
}

impl AgentConnection {
    pub fn new(agent_id: String, keys: AgentKeys, hostname: String, public_ip: String) -> Self {
        Self {
            agent_id,
            keys,
            last_seen: SystemTime::now(),
            health_sender: None,
            hostname,
            public_ip,
        }
    }

    pub fn update_last_seen(&mut self) {
        self.last_seen = SystemTime::now();
    }

    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_seen.elapsed().unwrap_or(Duration::MAX) > timeout
    }
}

#[derive(Debug, Clone)]
pub struct KeyManager {
    // Store active agent connections by agent_id
    agent_connections: Arc<Mutex<HashMap<String, AgentConnection>>>,
    // Port assignment
    next_port: Arc<Mutex<u32>>,
    // Connection timeout (default 5 minutes)
    connection_timeout: Duration,
}

impl KeyManager {
    pub fn new() -> Self {
        Self {
            agent_connections: Arc::new(Mutex::new(HashMap::new())),
            next_port: Arc::new(Mutex::new(51820)), // Start from standard WireGuard port
            connection_timeout: Duration::from_secs(300), // 5 minutes
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.connection_timeout = timeout;
        self
    }

    /// Register a new agent connection with agent-provided public key
    pub fn register_agent(
        &self,
        agent_id: &str,
        hostname: &str,
        public_ip: &str,
        agent_public_key: &str,
    ) -> Result<AgentKeys, Box<dyn std::error::Error>> {
        // Agent provides its own public key - we no longer generate keys

        // Assign a unique port
        let listen_port = {
            let mut port = self.next_port.lock().unwrap();
            let assigned_port = *port;
            *port += 1;
            assigned_port
        };

        let agent_keys = AgentKeys {
            private_key: String::new(), // No longer stored on control plane
            public_key: agent_public_key.to_string(),
            listen_port,
        };

        // Create and store the connection
        let connection = AgentConnection::new(
            agent_id.to_string(),
            agent_keys.clone(),
            hostname.to_string(),
            public_ip.to_string(),
        );

        {
            let mut connections = self.agent_connections.lock().unwrap();
            connections.insert(agent_id.to_string(), connection);
        }

        println!("Registered agent {} with WireGuard configuration", agent_id);
        println!("  Agent Public Key: {}", agent_public_key);
        println!("  Listen Port: {}", listen_port);

        Ok(agent_keys)
    }

    /// Generate new WireGuard keys for an agent (legacy method - deprecated)
    #[deprecated(note = "Agents now generate their own keys. Use register_agent instead.")]
    pub fn generate_agent_keys(
        &self,
        _agent_id: &str,
    ) -> Result<AgentKeys, Box<dyn std::error::Error>> {
        Err("Key generation is now handled by agents".into())
    }

    /// Update agent's last seen timestamp
    pub fn update_agent_activity(&self, agent_id: &str) {
        let mut connections = self.agent_connections.lock().unwrap();
        if let Some(connection) = connections.get_mut(agent_id) {
            connection.update_last_seen();
        }
    }

    /// Get existing keys for an agent
    pub fn get_agent_keys(&self, agent_id: &str) -> Option<AgentKeys> {
        let connections = self.agent_connections.lock().unwrap();
        connections.get(agent_id).map(|conn| conn.keys.clone())
    }

    /// Get agent connection info
    pub fn get_agent_connection(&self, agent_id: &str) -> Option<AgentConnection> {
        let connections = self.agent_connections.lock().unwrap();
        connections.get(agent_id).cloned()
    }

    /// Remove agent connection and keys
    pub fn remove_agent_keys(&self, agent_id: &str) -> bool {
        let mut connections = self.agent_connections.lock().unwrap();
        connections.remove(agent_id).is_some()
    }

    /// Clean up expired agent connections
    pub fn cleanup_expired_agents(&self) -> Vec<String> {
        let mut connections = self.agent_connections.lock().unwrap();
        let mut expired_agents = Vec::new();

        connections.retain(|agent_id, connection| {
            if connection.is_expired(self.connection_timeout) {
                expired_agents.push(agent_id.clone());
                false
            } else {
                true
            }
        });

        expired_agents
    }

    /// Generate peer keys for client connections
    pub fn generate_peer_keys() -> Result<(String, String), Box<dyn std::error::Error>> {
        let private_secret = StaticSecret::random();
        let public_key = PublicKey::from(&private_secret);

        let private_key_bytes: [u8; 32] = private_secret.to_bytes();
        let public_key_bytes: [u8; 32] = public_key.to_bytes();

        let private_key = base64::engine::general_purpose::STANDARD.encode(private_key_bytes);
        let public_key = base64::engine::general_purpose::STANDARD.encode(public_key_bytes);

        Ok((private_key, public_key))
    }

    /// List all active agents (non-expired)
    pub fn list_agents(&self) -> Vec<String> {
        let connections = self.agent_connections.lock().unwrap();
        connections
            .iter()
            .filter(|(_, conn)| !conn.is_expired(self.connection_timeout))
            .map(|(agent_id, _)| agent_id.clone())
            .collect()
    }

    /// List all registered agents (including expired)
    pub fn list_all_agents(&self) -> Vec<String> {
        let connections = self.agent_connections.lock().unwrap();
        connections.keys().cloned().collect()
    }

    /// Get count of active vs total agents
    pub fn get_agent_counts(&self) -> (usize, usize) {
        let connections = self.agent_connections.lock().unwrap();
        let total = connections.len();
        let active = connections
            .values()
            .filter(|conn| !conn.is_expired(self.connection_timeout))
            .count();
        (active, total)
    }

    /// Get next available port (for testing/debugging)
    pub fn get_next_port(&self) -> u32 {
        let port = self.next_port.lock().unwrap();
        *port
    }
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}

// Re-export commonly used types for convenience
pub use agent_manager::{AgentManager, AgentStats};
pub use config::Config;
pub use server::{TlsServer, TlsServerBuilder};
pub use service::VPN9ControlPlane;
pub use update_manager::UpdateManager;

/// Current version of the VPN9 Control Plane
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default configuration values
pub mod defaults {
    /// Default bind address for the control plane server
    pub const BIND_ADDRESS: &str = "0.0.0.0:50051";
    /// Default version string
    pub const VERSION: &str = "1.0.0";
    /// Default update path
    pub const UPDATE_PATH: &str = "./updates/";
    /// Default TLS certificate path
    pub const TLS_CERT_PATH: &str = "./certs/server.crt";
    /// Default TLS key path
    pub const TLS_KEY_PATH: &str = "./certs/server.key";
    /// Default TLS domain
    pub const TLS_DOMAIN: &str = "vpn9-control-plane";
}

/// Error types used throughout the control plane
pub mod error {
    use std::fmt;

    /// Configuration-related errors
    #[derive(Debug)]
    pub enum ConfigError {
        /// Missing required environment variable
        MissingEnvVar(String),
        /// Invalid configuration value
        InvalidValue(String),
        /// File not found
        FileNotFound(String),
        /// Permission denied
        PermissionDenied(String),
    }

    impl fmt::Display for ConfigError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                ConfigError::MissingEnvVar(var) => {
                    write!(f, "Missing environment variable: {}", var)
                }
                ConfigError::InvalidValue(msg) => write!(f, "Invalid configuration value: {}", msg),
                ConfigError::FileNotFound(path) => write!(f, "File not found: {}", path),
                ConfigError::PermissionDenied(msg) => write!(f, "Permission denied: {}", msg),
            }
        }
    }

    impl std::error::Error for ConfigError {}
}

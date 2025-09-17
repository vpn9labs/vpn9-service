use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::time::Duration;

use tonic::transport::{Certificate, Channel, ClientTlsConfig};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use vpn9_core::control_plane::control_plane_client::ControlPlaneClient;
use vpn9_core::control_plane::{
    AgentSubscriptionRequest, HealthResponse, agent_subscription_message::Message,
};

use tokio::sync::{Mutex, RwLock};

use crate::runtime_security::RuntimeSecurity;
use crate::secure_system_info::{OsInfo, collect_os_info};
use crate::version::get_version;
use crate::wireguard_manager::WireGuardManager;

pub struct VPN9Agent {
    agent_id: Uuid,
    control_plane_url: String,
    agent_version: String,
    heartbeat_interval: Duration,
    runtime_security: RuntimeSecurity,
    wireguard_manager: Arc<WireGuardManager>,
    lease_state: Arc<RwLock<HashMap<String, LeaseInfo>>>,
}

#[derive(Debug, Clone)]
struct LeaseInfo {
    nonce: Vec<u8>,
    version: u64,
}

impl VPN9Agent {
    pub fn new(control_plane_url: String) -> Self {
        fn derive_stable_agent_id() -> Uuid {
            if let Ok(s) = std::env::var("VPN9_AGENT_ID") {
                if let Ok(id) = Uuid::parse_str(s.trim()) {
                    return id;
                }
            }
            if let Ok(machine_id) = fs::read_to_string("/etc/machine-id") {
                let name = format!("vpn9-agent:{}", machine_id.trim());
                return Uuid::new_v5(&Uuid::NAMESPACE_OID, name.as_bytes());
            }
            if let Ok(hn) = std::env::var("HOSTNAME") {
                let name = format!("vpn9-agent:{}", hn.trim());
                return Uuid::new_v5(&Uuid::NAMESPACE_DNS, name.as_bytes());
            }
            Uuid::new_v4()
        }
        Self {
            agent_id: derive_stable_agent_id(),
            control_plane_url,
            agent_version: get_version(),
            heartbeat_interval: Duration::from_secs(60),
            runtime_security: RuntimeSecurity::new(),
            wireguard_manager: Arc::new(WireGuardManager::new()),
            lease_state: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn with_version(mut self, version: String) -> Self {
        self.agent_version = version;
        self
    }

    pub fn with_heartbeat_interval(mut self, interval: Duration) -> Self {
        self.heartbeat_interval = interval;
        self
    }

    async fn create_control_plane_client(
        &self,
    ) -> Result<ControlPlaneClient<Channel>, Box<dyn std::error::Error>> {
        info!("Connecting to control plane with TLS");

        // Check if we should use a custom CA certificate
        let ca_cert_path = std::env::var("VPN9_TLS_CA_CERT_PATH").ok();
        let domain_name =
            std::env::var("VPN9_TLS_DOMAIN").unwrap_or_else(|_| "vpn9-control-plane".to_string());

        let mut tls_config = ClientTlsConfig::new().domain_name(domain_name);

        // If a custom CA certificate is provided, use it
        if let Some(ca_path) = ca_cert_path {
            info!("Using custom CA certificate from: {}", ca_path);
            let ca_cert = fs::read(&ca_path)
                .map_err(|e| format!("Failed to read CA certificate file {ca_path}: {e}"))?;
            let ca_certificate = Certificate::from_pem(ca_cert);
            tls_config = tls_config.ca_certificate(ca_certificate);
        }

        let channel = Channel::from_shared(self.control_plane_url.clone())?
            .tls_config(tls_config)?
            .connect()
            .await?;

        Ok(ControlPlaneClient::new(channel))
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!(
            "Starting VPN9 Agent version {} with agent_id {}",
            self.agent_version, self.agent_id
        );

        // Initialize secure runtime environment
        if let Err(e) = self.runtime_security.initialize_secure_runtime() {
            warn!("Failed to initialize secure runtime: {}", e);
            warn!("Continuing with reduced security guarantees...");
        }

        let os_info = collect_os_info().await;
        loop {
            match self.run_once(&os_info).await {
                Ok(_) => return Ok(()),
                Err(err) => {
                    error!(
                        ?err,
                        "Control plane session ended with error; reconnecting soon"
                    );
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    async fn run_once(&self, os_info: &OsInfo) -> Result<(), Box<dyn std::error::Error>> {
        let mut client = self.create_control_plane_client().await?;
        self.subscribe_to_control_plane(&mut client, os_info)
            .await?;
        self.run_main_loop().await
    }

    async fn subscribe_to_control_plane(
        &self,
        client: &mut ControlPlaneClient<tonic::transport::Channel>,
        os_info: &OsInfo,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let request = tonic::Request::new(AgentSubscriptionRequest {
            agent_id: self.agent_id.to_string(),
            hostname: os_info.hostname.clone(),
            os_version: os_info.os_version.clone(),
            kernel_version: os_info.kernel_version.clone(),
            public_ip: os_info
                .public_ip
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            cpu_count: os_info.cpu_count as i32,
            total_memory_mb: os_info.total_memory_mb as i32,
            wg_public_key: String::new(),
        });

        info!("Subscribing to control plane...");
        info!("Using agent_id={}", self.agent_id);
        let mut response_stream = client.subscribe_agent(request).await?.into_inner();

        // Handle the registration response and maintain subscription
        let wg_manager = self.wireguard_manager.clone();
        let lease_state = self.lease_state.clone();
        let health_client = Arc::new(Mutex::new(client.clone()));
        let health_client_task = health_client.clone();
        tokio::spawn(async move {
            while let Some(message) = response_stream.message().await.unwrap_or(None) {
                if let Some(msg) = message.message {
                    match msg {
                        Message::AgentRegistration(registration) => {
                            info!("🎉 Agent registered successfully!");
                            info!("  Status: {}", registration.status);
                            info!("  Control Plane Public Key: {}", registration.wg_public_key);
                            info!("  WireGuard Listen Port: {}", registration.wg_listen_port);
                            // Configure WireGuard with private key received from control plane
                            let private_key = registration.wg_private_key.clone();
                            let public_key = registration.wg_public_key.clone();

                            match wg_manager.configure_wireguard(
                                private_key,
                                public_key,
                                registration.wg_listen_port,
                            ) {
                                Ok(_) => {
                                    info!(
                                        "🔗 WireGuard VPN is now active and ready for connections!"
                                    );

                                    // Display interface status
                                    if let Ok(status) = wg_manager.get_interface_status() {
                                        info!("📊 WireGuard Interface Status:\n{}", status);
                                    }
                                }
                                Err(e) => {
                                    error!("❌ Failed to configure WireGuard: {}", e);
                                    error!(
                                        "The agent will continue running but VPN functionality will be disabled."
                                    );
                                }
                            }
                        }
                        Message::PeerAdd(peer_req) => {
                            info!("📡 Peer registration request received:");
                            info!("  Agent ID: {}", peer_req.agent_id);
                            info!("  Public Key: {}", peer_req.public_key);
                            info!("  Lease Version: {}", peer_req.lease_version);

                            {
                                let mut leases = lease_state.write().await;
                                leases.insert(
                                    peer_req.public_key.clone(),
                                    LeaseInfo {
                                        nonce: peer_req.lease_nonce.clone(),
                                        version: peer_req.lease_version,
                                    },
                                );
                            }

                            // Add the peer to our WireGuard interface using provided allowed_ips
                            let allowed_ips = if !peer_req.allowed_ips.is_empty() {
                                peer_req.allowed_ips.clone()
                            } else {
                                // Fallback: allow all IPv4 if not specified
                                vec!["0.0.0.0/0".to_string()]
                            };

                            match wg_manager.add_peer(&peer_req.public_key, allowed_ips, None) {
                                Ok(_) => {
                                    info!("✅ Peer added to WireGuard interface");
                                }
                                Err(e) => {
                                    error!("❌ Failed to add peer: {}", e);
                                }
                            }
                        }
                        Message::PeerRemove(peer_rm) => {
                            info!(
                                "🗑️ Peer removal request received for: {}",
                                peer_rm.public_key
                            );
                            let mut should_remove = true;
                            {
                                let mut leases = lease_state.write().await;
                                if let Some(current) = leases.get(&peer_rm.public_key) {
                                    if !peer_rm.expected_nonce.is_empty()
                                        && current.nonce != peer_rm.expected_nonce
                                    {
                                        warn!(
                                            "⚠️ Lease nonce mismatch; keeping peer {} (expected {:?}, have {:?})",
                                            peer_rm.public_key,
                                            peer_rm.expected_nonce,
                                            current.nonce
                                        );
                                        should_remove = false;
                                    } else {
                                        leases.remove(&peer_rm.public_key);
                                    }
                                } else if !peer_rm.expected_nonce.is_empty() {
                                    warn!(
                                        "⚠️ Removal requested with nonce but peer {} not tracked locally",
                                        peer_rm.public_key
                                    );
                                }
                            }

                            if should_remove {
                                match wg_manager.remove_peer(&peer_rm.public_key) {
                                    Ok(_) => info!("✅ Peer removed from WireGuard interface"),
                                    Err(e) => error!("❌ Failed to remove peer: {}", e),
                                }
                            } else {
                                info!(
                                    "ℹ️ Skipping removal for {} due to nonce mismatch",
                                    peer_rm.public_key
                                );
                            }
                        }
                        Message::LeaseUpdate(update) => {
                            info!(
                                "🔁 Lease update received for {} (version {})",
                                update.public_key, update.lease_version
                            );
                            let mut should_remove = false;
                            let mut should_store = true;
                            {
                                let mut leases = lease_state.write().await;
                                if let Some(current) = leases.get(&update.public_key) {
                                    if update.lease_version <= current.version
                                        && current.nonce == update.lease_nonce
                                    {
                                        debug!(
                                            "Lease update version {} not newer than cached {}; ignoring",
                                            update.lease_version, current.version
                                        );
                                        should_store = false;
                                    } else if current.nonce != update.lease_nonce {
                                        should_remove = true;
                                        leases.remove(&update.public_key);
                                        should_store = false;
                                    } else {
                                        leases.insert(
                                            update.public_key.clone(),
                                            LeaseInfo {
                                                nonce: update.lease_nonce.clone(),
                                                version: update.lease_version,
                                            },
                                        );
                                    }
                                } else {
                                    leases.insert(
                                        update.public_key.clone(),
                                        LeaseInfo {
                                            nonce: update.lease_nonce.clone(),
                                            version: update.lease_version,
                                        },
                                    );
                                }
                            }

                            if should_remove {
                                info!(
                                    "🔒 Lease nonce rotated elsewhere; removing local peer {}",
                                    update.public_key
                                );
                                match wg_manager.remove_peer(&update.public_key) {
                                    Ok(_) => info!("✅ Peer removed after lease update"),
                                    Err(e) => {
                                        error!("❌ Failed to remove peer after lease update: {}", e)
                                    }
                                }
                            } else if should_store {
                                info!(
                                    "Lease metadata refreshed for {} (version {})",
                                    update.public_key, update.lease_version
                                );
                            }
                        }
                        Message::HealthCheck(health_check) => {
                            debug!(
                                "💓 Health check received from control plane (timestamp: {}, agent_id={})",
                                health_check.timestamp, health_check.agent_id
                            );

                            let response = HealthResponse {
                                agent_id: health_check.agent_id.clone(),
                                timestamp: health_check.timestamp,
                                status: "ok".to_string(),
                            };

                            let mut client_guard = health_client_task.lock().await;
                            if let Err(err) = client_guard.report_health(response).await {
                                warn!("⚠️ Failed to report health to control plane: {}", err);
                            } else {
                                debug!("✅ Health response sent to control plane");
                            }
                        }
                        Message::HealthResponse(_health_response) => {
                            debug!("💚 Health response received from control plane");
                        }
                        Message::AgentDisconnect(disconnect) => {
                            info!("🚪 Disconnect message received from control plane:");
                            info!("  Agent ID: {}", disconnect.agent_id);
                            info!("  Reason: {}", disconnect.reason);
                            info!("Agent will now shut down gracefully...");
                            break;
                        }
                    }
                }
            }
            info!("Control plane subscription stream ended");
        });

        info!("Subscription established with control plane");
        info!("Agent {} now streaming", self.agent_id);
        Ok(())
    }

    async fn run_main_loop(&self) -> Result<(), Box<dyn std::error::Error>> {
        let secure_status = if self.runtime_security.is_secure_mode() {
            "SECURE MODE"
        } else {
            "STANDARD MODE"
        };

        info!(
            "Agent running in {} - Heartbeat every {} seconds",
            secure_status,
            self.heartbeat_interval.as_secs()
        );

        let mut heartbeat_interval = tokio::time::interval(self.heartbeat_interval);

        loop {
            heartbeat_interval.tick().await;

            // Main agent functionality would go here
            let vpn_status = if self.wireguard_manager.is_configured() {
                "VPN ACTIVE"
            } else {
                "VPN INACTIVE"
            };

            debug!(
                "Agent heartbeat - version: {} ({}) - {}",
                self.agent_version, secure_status, vpn_status
            );

            // TODO: Add more VPN functionality here
            // - Monitor VPN connection health
            // - Report bandwidth statistics
            // - Handle configuration updates
            // - Report status to control plane
        }
    }

    pub fn version(&self) -> &str {
        &self.agent_version
    }

    pub fn control_plane_url(&self) -> &str {
        &self.control_plane_url
    }

    pub fn is_secure_mode(&self) -> bool {
        self.runtime_security.is_secure_mode()
    }

    pub fn secure_shutdown(&self) {
        info!("Agent received shutdown signal");
        self.runtime_security.secure_shutdown();
    }

    pub fn agent_id(&self) -> &Uuid {
        &self.agent_id
    }

    pub fn wireguard_manager(&self) -> Arc<WireGuardManager> {
        self.wireguard_manager.clone()
    }
}

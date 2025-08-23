use std::fs;
use std::sync::Arc;
use std::time::Duration;

use tonic::transport::{Certificate, Channel, ClientTlsConfig};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use vpn9_core::control_plane::control_plane_client::ControlPlaneClient;
use vpn9_core::control_plane::{AgentSubscriptionRequest, agent_subscription_message::Message};

use crate::runtime_security::RuntimeSecurity;
use crate::secure_system_info::{OsInfo, collect_os_info};
use crate::secure_update_manager::SecureUpdateManager;
use crate::version::get_version;
use crate::wireguard_manager::WireGuardManager;

pub struct VPN9Agent {
    agent_id: Uuid,
    control_plane_url: String,
    agent_version: String,
    heartbeat_interval: Duration,
    runtime_security: RuntimeSecurity,
    wireguard_manager: Arc<WireGuardManager>,
    wg_private_key: Option<String>,
    wg_public_key: Option<String>,
}

impl VPN9Agent {
    pub fn new(control_plane_url: String) -> Self {
        Self {
            agent_id: Uuid::new_v4(),
            control_plane_url,
            agent_version: get_version(),
            heartbeat_interval: Duration::from_secs(60),
            runtime_security: RuntimeSecurity::new(),
            wireguard_manager: Arc::new(WireGuardManager::new()),
            wg_private_key: None,
            wg_public_key: None,
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
                .map_err(|e| format!("Failed to read CA certificate file {}: {}", ca_path, e))?;
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
        info!("Starting VPN9 Agent version {}", self.agent_version);

        // Initialize secure runtime environment
        if let Err(e) = self.runtime_security.initialize_secure_runtime() {
            warn!("Failed to initialize secure runtime: {}", e);
            warn!("Continuing with reduced security guarantees...");
        }

        // Generate WireGuard keys locally
        info!("Generating WireGuard keys locally...");
        let (private_key, public_key) = WireGuardManager::generate_keypair()?;
        self.wg_private_key = Some(private_key.clone());
        self.wg_public_key = Some(public_key.clone());
        info!("Generated WireGuard public key: {}", public_key);
        debug!(
            "Private key length: {}, Public key length: {}",
            private_key.len(),
            public_key.len()
        );

        // Connect to control plane
        let mut client = self.create_control_plane_client().await?;

        // Collect system info and subscribe to control plane
        let os_info = collect_os_info().await;
        self.subscribe_to_control_plane(&mut client, &os_info)
            .await?;

        // Start update checker in background
        self.start_update_checker().await?;

        // Run main agent loop
        self.run_main_loop().await
    }

    async fn subscribe_to_control_plane(
        &self,
        client: &mut ControlPlaneClient<tonic::transport::Channel>,
        os_info: &OsInfo,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let wg_public_key = self.wg_public_key.clone().unwrap_or_default();
        debug!(
            "Sending WireGuard public key in subscription: {}",
            &wg_public_key
        );

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
            wg_public_key,
        });

        info!("Subscribing to control plane...");
        let mut response_stream = client.subscribe_agent(request).await?.into_inner();

        // Handle the registration response and maintain subscription
        let wg_manager = self.wireguard_manager.clone();
        let agent_private_key = self.wg_private_key.clone();
        let agent_public_key = self.wg_public_key.clone();
        tokio::spawn(async move {
            while let Some(message) = response_stream.message().await.unwrap_or(None) {
                if let Some(msg) = message.message {
                    match msg {
                        Message::AgentRegistration(registration) => {
                            info!("🎉 Agent registered successfully!");
                            info!("  Status: {}", registration.status);
                            info!("  Control Plane Public Key: {}", registration.wg_public_key);
                            info!("  WireGuard Listen Port: {}", registration.wg_listen_port);
                            debug!(
                                "  Agent Private Key available: {}",
                                agent_private_key.is_some()
                            );
                            debug!(
                                "  Agent Public Key available: {}",
                                agent_public_key.is_some()
                            );

                            // Configure WireGuard with our locally generated private key
                            let private_key = agent_private_key.clone().unwrap();
                            let public_key = agent_public_key.clone().unwrap();

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
                        Message::PeerRegistrationRequest(peer_req) => {
                            info!("📡 Peer registration request received:");
                            info!("  Agent ID: {}", peer_req.agent_id);
                            info!("  Public Key: {}", peer_req.public_key);

                            // Add the peer to our WireGuard interface
                            // In production, the allowed IPs should come from the control plane
                            let allowed_ips = vec!["0.0.0.0/0".to_string()]; // Allow all traffic through this peer

                            match wg_manager.add_peer(&peer_req.public_key, allowed_ips, None) {
                                Ok(_) => {
                                    info!("✅ Peer added to WireGuard interface");
                                }
                                Err(e) => {
                                    error!("❌ Failed to add peer: {}", e);
                                }
                            }
                        }
                        Message::HealthCheck(health_check) => {
                            debug!(
                                "💓 Health check received from control plane (timestamp: {})",
                                health_check.timestamp
                            );

                            // Send health response back (in a real implementation, this would be sent back through the stream)
                            // For now, we just acknowledge it locally
                            debug!("✅ Responding to health check");
                        }
                        Message::HealthResponse(_health_response) => {
                            // This would be received if we sent a health check to the control plane
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
        Ok(())
    }

    async fn start_update_checker(&self) -> Result<(), Box<dyn std::error::Error>> {
        let update_client = self.create_control_plane_client().await?;
        let mut update_manager = SecureUpdateManager::new(update_client)
            .with_version(self.agent_version.clone())
            .with_update_interval(Duration::from_secs(300)); // Check every 5 minutes

        tokio::spawn(async move {
            update_manager.start_update_checker().await;
        });

        info!("Secure update checker started - checking every 5 minutes");
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

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::time::{interval, sleep};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{debug, error, info, warn};

use vpn9_core::control_plane::{
    AgentRegistration, AgentSubscriptionMessage, AgentSubscriptionRequest, HealthCheck, PeerAdd,
    PeerRemove, agent_subscription_message::Message,
};

use crate::device_registry::DeviceRegistry;
use crate::device_registry::RegistryDiff;
use crate::keystore::StrongBoxKeystore;
use crate::{AgentKeys, KeyManager};

/// Manages agent subscriptions and registrations
pub struct AgentManager {
    key_manager: KeyManager,
    registry: Option<std::sync::Arc<DeviceRegistry>>,
    keystore: Option<std::sync::Arc<StrongBoxKeystore>>,
}

impl AgentManager {
    pub fn new() -> Self {
        Self::new_with_cleanup_with_registry(true, None, None)
    }

    pub fn new_with_cleanup(start_cleanup: bool) -> Self {
        Self::new_with_cleanup_with_registry(start_cleanup, None, None)
    }

    pub fn new_with_registry(registry: std::sync::Arc<DeviceRegistry>) -> Self {
        Self::new_with_cleanup_with_registry(true, Some(registry), None)
    }

    pub fn new_with_cleanup_with_registry(
        start_cleanup: bool,
        registry: Option<std::sync::Arc<DeviceRegistry>>,
        keystore: Option<std::sync::Arc<StrongBoxKeystore>>,
    ) -> Self {
        let manager = Self {
            key_manager: KeyManager::new(),
            registry,
            keystore,
        };

        // Start cleanup task only if requested (for production use)
        if start_cleanup {
            manager.start_cleanup_task();
        }
        manager
    }

    /// Start a background task to clean up expired agents
    fn start_cleanup_task(&self) {
        let key_manager = self.key_manager.clone();
        tokio::spawn(async move {
            let mut cleanup_interval = interval(Duration::from_secs(60)); // Clean up every minute

            loop {
                cleanup_interval.tick().await;
                let expired_agents = key_manager.cleanup_expired_agents();

                if !expired_agents.is_empty() {
                    info!(
                        expired_count = expired_agents.len(),
                        expired_agents = ?expired_agents,
                        "Cleaned up expired agent connections"
                    );
                }
            }
        });
    }

    /// Subscribe an agent to the control plane
    pub async fn subscribe_agent(
        &self,
        request: Request<AgentSubscriptionRequest>,
    ) -> Result<Response<ReceiverStream<Result<AgentSubscriptionMessage, Status>>>, Status> {
        let req = request.into_inner();
        info!(
            agent_id = %req.agent_id,
            hostname = %req.hostname,
            os_version = %req.os_version,
            kernel_version = %req.kernel_version,
            public_ip = %req.public_ip,
            cpu_count = req.cpu_count,
            total_memory_mb = req.total_memory_mb,
            "Agent registration and subscription request received"
        );

        // Increase channel buffer to reduce backpressure during seeding
        let (tx, rx) = mpsc::channel(128);
        let agent_id = req.agent_id.clone();

        // Get or create relay keys in keystore (public+private)
        let (relay_pub_b64, relay_priv_b64) = if let Some(ks) = self.keystore.as_ref() {
            match ks.get_or_create_and_decrypt(&agent_id).await {
                Ok(t) => t,
                Err(e) => {
                    error!(agent_id = %agent_id, error=%e.to_string(), "Keystore failed to get_or_create keys");
                    return Err(Status::internal("Failed to provision relay keys"));
                }
            }
        } else {
            // Fallback to agent-provided key (testing only); no private key delivery
            (req.wg_public_key.clone(), String::new())
        };

        // Register the agent with connection tracking
        let agent_keys = match self.key_manager.register_agent(
            &agent_id,
            &req.hostname,
            &req.public_ip,
            &relay_pub_b64,
        ) {
            Ok(keys) => {
                debug!(
                    agent_id = %agent_id,
                    listen_port = keys.listen_port,
                    hostname = %req.hostname,
                    public_ip = %req.public_ip,
                    "Agent registered successfully with connection tracking"
                );
                keys
            }
            Err(e) => {
                error!(
                    agent_id = %agent_id,
                    error = %e,
                    "Failed to register agent"
                );
                return Err(Status::internal("Failed to register agent"));
            }
        };

        let key_manager_clone = self.key_manager.clone();
        let registry = self.registry.clone();
        tokio::spawn(async move {
            // Send initial registration confirmation with WireGuard configuration
            let subscription_msg = AgentSubscriptionMessage {
                agent_id: agent_id.clone(),
                message: Some(Message::AgentRegistration(AgentRegistration {
                    status: "registered_and_subscribed".to_string(),
                    wg_public_key: agent_keys.public_key,
                    wg_private_key: relay_priv_b64,
                    wg_listen_port: agent_keys.listen_port,
                })),
            };

            if tx.send(Ok(subscription_msg)).await.is_ok() {
                info!(
                    agent_id = %agent_id,
                    "Agent registration completed successfully"
                );
            } else {
                warn!(
                    agent_id = %agent_id,
                    "Failed to send registration response - client disconnected"
                );
                return;
            }

            // Seed device peers from DeviceRegistry with chunking to avoid backpressure
            if let Some(reg) = registry.as_ref() {
                let devices = reg.list_all_devices().await;
                if !devices.is_empty() {
                    const SEED_CHUNK_SIZE: usize = 50;
                    info!(
                        agent_id = %agent_id,
                        device_count = devices.len(),
                        chunk_size = SEED_CHUNK_SIZE,
                        "Seeding device peers from registry"
                    );
                    for chunk in devices.chunks(SEED_CHUNK_SIZE) {
                        for dev in chunk.iter() {
                            let msg = AgentSubscriptionMessage {
                                agent_id: agent_id.clone(),
                                message: Some(Message::PeerAdd(PeerAdd {
                                    agent_id: agent_id.clone(),
                                    public_key: dev.public_key.clone(),
                                    allowed_ips: dev.allowed_ips.clone(),
                                    ipv6: dev.ipv6.clone(),
                                })),
                            };
                            if tx.send(Ok(msg)).await.is_err() {
                                warn!(agent_id = %agent_id, "Client disconnected while seeding peers");
                                break;
                            }
                        }
                        // Yield between chunks to give the client time to drain
                        tokio::task::yield_now().await;
                    }
                } else {
                    debug!(agent_id = %agent_id, "No devices found in registry to seed");
                }
            }

            // Start health monitoring
            let mut health_interval = interval(Duration::from_secs(30)); // Health check every 30 seconds
            let mut missed_health_checks = 0;
            const MAX_MISSED_CHECKS: u32 = 3;

            // Subscribe to registry diffs, if available
            let mut updates_rx = registry.as_ref().map(|r| r.subscribe_updates());

            loop {
                tokio::select! {
                    _ = health_interval.tick() => {
                        // Send health check
                        let health_check = AgentSubscriptionMessage {
                            agent_id: agent_id.clone(),
                            message: Some(Message::HealthCheck(HealthCheck {
                                agent_id: agent_id.clone(),
                                timestamp: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs() as i64,
                            })),
                        };

                        if tx.send(Ok(health_check)).await.is_err() {
                            warn!(
                                agent_id = %agent_id,
                                "Health check failed - client disconnected"
                            );
                            break;
                        }

                        missed_health_checks += 1;
                        if missed_health_checks > MAX_MISSED_CHECKS {
                            error!(
                                agent_id = %agent_id,
                                missed_checks = missed_health_checks,
                                "Agent failed health checks, removing connection"
                            );
                            break;
                        }
                    }

                    // Forward registry diffs to the subscribed agent
                    Some(diff) = async {
                        match &mut updates_rx {
                            Some(rx) => rx.recv().await.ok(),
                            None => None,
                        }
                    } => {
                        match diff {
                            RegistryDiff::Added(dev) => {
                                let msg = AgentSubscriptionMessage {
                                    agent_id: agent_id.clone(),
                                    message: Some(Message::PeerAdd(PeerAdd {
                                        agent_id: agent_id.clone(),
                                        public_key: dev.public_key.clone(),
                                        allowed_ips: dev.allowed_ips.clone(),
                                        ipv6: dev.ipv6.clone(),
                                    })),
                                };
                                if tx.send(Ok(msg)).await.is_err() {
                                    warn!(agent_id = %agent_id, "Client disconnected while sending device add");
                                    break;
                                }
                            }
                            RegistryDiff::Removed { public_key, .. } => {
                                let msg = AgentSubscriptionMessage {
                                    agent_id: agent_id.clone(),
                                    message: Some(Message::PeerRemove(
                                        PeerRemove {
                                        agent_id: agent_id.clone(),
                                        public_key,
                                        }
                                    )),
                                };
                                if tx.send(Ok(msg)).await.is_err() {
                                    warn!(agent_id = %agent_id, "Client disconnected while sending device remove");
                                    break;
                                }
                            }
                        }
                    }

                    // Simulate receiving health responses (in real implementation, this would be from agent)
                    _ = sleep(Duration::from_secs(35)) => {
                        // Update activity to keep connection alive
                        key_manager_clone.update_agent_activity(&agent_id);
                        missed_health_checks = 0; // Reset counter on activity
                        debug!(
                            agent_id = %agent_id,
                            "Agent activity detected, resetting health check counter"
                        );
                    }
                }
            }

            // Clean up when connection ends
            warn!(
                agent_id = %agent_id,
                "Agent subscription ended, cleaning up connection"
            );
            key_manager_clone.remove_agent_keys(&agent_id);
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    /// List all registered agents
    pub fn list_registered_agents(&self) -> Vec<String> {
        self.key_manager.list_agents()
    }

    /// Get WireGuard keys for a specific agent
    pub fn get_agent_keys(&self, agent_id: &str) -> Option<AgentKeys> {
        self.key_manager.get_agent_keys(agent_id)
    }

    /// Remove an agent from the system
    pub fn remove_agent(&self, agent_id: &str) -> bool {
        self.key_manager.remove_agent_keys(agent_id)
    }

    /// Get agent statistics with accurate active/total counts
    pub fn get_agent_stats(&self) -> AgentStats {
        let (active_count, total_count) = self.key_manager.get_agent_counts();
        let active_agents = self.key_manager.list_agents();

        AgentStats {
            total_agents: total_count,
            active_agents: active_count,
            registered_agents: active_agents,
        }
    }
}

impl Default for AgentManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about registered agents
#[derive(Debug, Clone)]
pub struct AgentStats {
    pub total_agents: usize,
    pub active_agents: usize,
    pub registered_agents: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_manager_creation() {
        let agent_manager = AgentManager::new_with_cleanup(false);
        let stats = agent_manager.get_agent_stats();
        assert_eq!(stats.total_agents, 0);
    }

    #[test]
    fn test_list_registered_agents_empty() {
        let agent_manager = AgentManager::new_with_cleanup(false);
        let agents = agent_manager.list_registered_agents();
        assert!(agents.is_empty());
    }
}

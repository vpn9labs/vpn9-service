use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::info;

use vpn9_core::control_plane::control_plane_server::ControlPlane;
use vpn9_core::control_plane::{
    AgentSubscriptionMessage, AgentSubscriptionRequest, HealthAck, HealthResponse,
};

use crate::AgentKeys;
use crate::agent_manager::AgentManager;
use crate::config::Config;
use crate::device_registry::DeviceRegistry;
use crate::keystore::StrongBoxKeystore;
use crate::lease_manager::LeaseManager;
use crate::preferred_relay::PreferredRelayDecryptor;

/// Main VPN9 Control Plane service that implements the gRPC interface
pub struct VPN9ControlPlane {
    config: Config,
    agent_manager: AgentManager,
    registry: Option<std::sync::Arc<DeviceRegistry>>,
}

impl VPN9ControlPlane {
    /// Create a new VPN9ControlPlane service instance
    pub fn new(config: Config) -> Self {
        info!(
            version = %config.current_version,
            "Initializing VPN9 Control Plane service"
        );

        let agent_manager = AgentManager::new(); // Use cleanup in production
        Self {
            config,
            agent_manager,
            registry: None,
        }
    }

    /// Preferred constructor: inject initialized device registry
    pub fn new_with_registry(config: Config, registry: std::sync::Arc<DeviceRegistry>) -> Self {
        info!(
            version = %config.current_version,
            "Initializing VPN9 Control Plane service (with registry)"
        );

        let agent_manager = AgentManager::new_with_registry(registry.clone());

        Self {
            config,
            agent_manager,
            registry: Some(registry),
        }
    }

    /// Preferred constructor: with registry and keystore
    pub fn new_with_registry_and_keystore(
        config: Config,
        registry: std::sync::Arc<DeviceRegistry>,
        keystore: std::sync::Arc<StrongBoxKeystore>,
        lease_manager: std::sync::Arc<LeaseManager>,
        preferred_relay: Option<std::sync::Arc<PreferredRelayDecryptor>>,
    ) -> Self {
        info!(
            version = %config.current_version,
            "Initializing VPN9 Control Plane service (with registry + keystore)"
        );

        let agent_manager = crate::agent_manager::AgentManager::new_with_cleanup_with_registry(
            true,
            Some(registry.clone()),
            Some(keystore),
            Some(lease_manager),
            preferred_relay,
        );

        Self {
            config,
            agent_manager,
            registry: Some(registry),
        }
    }
    /// Get the current version of the control plane
    pub fn current_version(&self) -> &str {
        &self.config.current_version
    }

    /// List all registered agents
    pub fn list_registered_agents(&self) -> Vec<String> {
        self.agent_manager.list_registered_agents()
    }

    /// Get WireGuard keys for a specific agent
    pub fn get_agent_keys(&self, agent_id: &str) -> Option<AgentKeys> {
        self.agent_manager.get_agent_keys(agent_id)
    }

    /// Get agent statistics
    pub fn get_agent_stats(&self) -> crate::agent_manager::AgentStats {
        self.agent_manager.get_agent_stats()
    }

    /// Remove an agent from the system
    pub fn remove_agent(&self, agent_id: &str) -> bool {
        self.agent_manager.remove_agent(agent_id)
    }
}

#[tonic::async_trait]
impl ControlPlane for VPN9ControlPlane {
    type SubscribeAgentStream = ReceiverStream<Result<AgentSubscriptionMessage, Status>>;

    /// Handle agent subscription and registration requests
    async fn subscribe_agent(
        &self,
        request: Request<AgentSubscriptionRequest>,
    ) -> Result<Response<Self::SubscribeAgentStream>, Status> {
        if self.registry.is_some() {
            info!("Device registry available; seeding peers on subscribe");
        }
        self.agent_manager.subscribe_agent(request).await
    }

    async fn report_health(
        &self,
        request: Request<HealthResponse>,
    ) -> Result<Response<HealthAck>, Status> {
        let body = request.into_inner();
        let accepted = self
            .agent_manager
            .record_health_response(&body.agent_id, body.timestamp, body.status)
            .await;
        Ok(Response::new(HealthAck { accepted }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_service() -> VPN9ControlPlane {
        let config = Config::default();
        let agent_manager = AgentManager::new_with_cleanup(false); // No cleanup in tests

        VPN9ControlPlane {
            config,
            agent_manager,
            registry: None,
        }
    }

    #[test]
    fn test_service_creation() {
        let service = create_test_service();
        assert_eq!(service.current_version(), "1.0.0");
    }

    #[test]
    fn test_list_registered_agents_empty() {
        let service = create_test_service();
        let agents = service.list_registered_agents();
        assert!(agents.is_empty());
    }

    #[test]
    fn test_get_agent_stats() {
        let service = create_test_service();
        let stats = service.get_agent_stats();
        assert_eq!(stats.total_agents, 0);
        assert_eq!(stats.active_agents, 0);
    }
}

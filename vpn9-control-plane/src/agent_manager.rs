use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{RwLock, mpsc};
use tokio::time::interval;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{debug, error, info, warn};

use vpn9_core::control_plane::{
    AgentRegistration, AgentSubscriptionMessage, AgentSubscriptionRequest, HealthCheck,
    LeaseUpdate, PeerAdd, PeerRemove, agent_subscription_message::Message,
};

use crate::device_registry::RegistryDiff;
use crate::device_registry::{DeviceRecord, DeviceRegistry};
use crate::keystore::StrongBoxKeystore;
use crate::lease_manager::{LeaseManager, LeaseState};
use crate::{AgentKeys, KeyManager};

/// Manages agent subscriptions and registrations
pub struct AgentManager {
    key_manager: KeyManager,
    registry: Option<std::sync::Arc<DeviceRegistry>>,
    keystore: Option<std::sync::Arc<StrongBoxKeystore>>,
    lease_manager: Option<std::sync::Arc<LeaseManager>>,
    lease_cache: std::sync::Arc<RwLock<HashMap<String, LeaseState>>>,
    health_trackers: std::sync::Arc<RwLock<HashMap<String, std::sync::Arc<AtomicU32>>>>,
}

impl AgentManager {
    fn owner_for(pubkey_b64: &str, active_agents: &[String]) -> Option<String> {
        if active_agents.is_empty() {
            return None;
        }
        let mut best: Option<(u128, &String)> = None;
        for agent in active_agents {
            let mut hasher = Sha256::new();
            hasher.update(pubkey_b64.as_bytes());
            hasher.update(b"|");
            hasher.update(agent.as_bytes());
            let digest = hasher.finalize();
            // Use first 16 bytes as u128 for better spread
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&digest[..16]);
            let score = u128::from_be_bytes(arr);
            match best {
                None => best = Some((score, agent)),
                Some((bscore, _)) if score > bscore => best = Some((score, agent)),
                _ => {}
            }
        }
        best.map(|(_, a)| a.clone())
    }

    async fn resolve_owner_for_device(
        device: &DeviceRecord,
        active_agents: &[String],
    ) -> Option<String> {
        AgentManager::owner_for(&device.public_key, active_agents)
    }

    fn peer_add_message(
        agent_id: &str,
        dev: &DeviceRecord,
        lease: &LeaseState,
    ) -> AgentSubscriptionMessage {
        AgentSubscriptionMessage {
            agent_id: agent_id.to_string(),
            message: Some(Message::PeerAdd(PeerAdd {
                agent_id: agent_id.to_string(),
                public_key: dev.public_key.clone(),
                allowed_ips: dev.allowed_ips.clone(),
                ipv6: dev.ipv6.clone(),
                lease_nonce: lease.nonce.clone(),
                lease_version: lease.version,
            })),
        }
    }

    fn peer_remove_message(
        agent_id: &str,
        public_key: &str,
        expected_nonce: Vec<u8>,
    ) -> AgentSubscriptionMessage {
        AgentSubscriptionMessage {
            agent_id: agent_id.to_string(),
            message: Some(Message::PeerRemove(PeerRemove {
                agent_id: agent_id.to_string(),
                public_key: public_key.to_string(),
                expected_nonce,
            })),
        }
    }

    fn lease_update_message(
        agent_id: &str,
        public_key: &str,
        lease: &LeaseState,
    ) -> AgentSubscriptionMessage {
        AgentSubscriptionMessage {
            agent_id: agent_id.to_string(),
            message: Some(Message::LeaseUpdate(LeaseUpdate {
                agent_id: agent_id.to_string(),
                public_key: public_key.to_string(),
                lease_nonce: lease.nonce.clone(),
                lease_version: lease.version,
            })),
        }
    }

    pub fn new() -> Self {
        Self::new_with_cleanup_with_registry(true, None, None, None)
    }

    pub fn new_with_cleanup(start_cleanup: bool) -> Self {
        Self::new_with_cleanup_with_registry(start_cleanup, None, None, None)
    }

    pub fn new_with_registry(registry: std::sync::Arc<DeviceRegistry>) -> Self {
        Self::new_with_cleanup_with_registry(true, Some(registry), None, None)
    }

    pub fn new_with_cleanup_with_registry(
        start_cleanup: bool,
        registry: Option<std::sync::Arc<DeviceRegistry>>,
        keystore: Option<std::sync::Arc<StrongBoxKeystore>>,
        lease_manager: Option<std::sync::Arc<LeaseManager>>,
    ) -> Self {
        let manager = Self {
            key_manager: KeyManager::new(),
            registry,
            keystore,
            lease_manager,
            lease_cache: std::sync::Arc::new(RwLock::new(HashMap::new())),
            health_trackers: std::sync::Arc::new(RwLock::new(HashMap::new())),
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

        let health_counter = {
            let counter = std::sync::Arc::new(AtomicU32::new(0));
            let mut trackers = self.health_trackers.write().await;
            trackers.insert(agent_id.clone(), counter.clone());
            counter
        };
        let health_trackers = self.health_trackers.clone();
        let key_manager_clone = self.key_manager.clone();
        let registry = self.registry.clone();
        let lease_manager = self.lease_manager.clone();
        let lease_cache = self.lease_cache.clone();
        let health_counter_clone = health_counter.clone();
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
                            let active = key_manager_clone.list_agents();
                            let owner = AgentManager::resolve_owner_for_device(dev, &active).await;
                            if owner.as_deref() == Some(&agent_id) {
                                if let Some(ref lm) = lease_manager {
                                    match lm.acquire(&dev.id).await {
                                        Ok(outcome) => {
                                            {
                                                let mut cache = lease_cache.write().await;
                                                cache.insert(
                                                    dev.public_key.clone(),
                                                    outcome.lease.clone(),
                                                );
                                            }
                                            info!(
                                                agent_id = %agent_id,
                                                device_pub = %dev.public_key,
                                                lease_version = outcome.lease.version,
                                                "Ownership match during seed: issuing PeerAdd with lease"
                                            );
                                            let msg = AgentManager::peer_add_message(
                                                &agent_id,
                                                dev,
                                                &outcome.lease,
                                            );
                                            if tx.send(Ok(msg)).await.is_err() {
                                                warn!(agent_id = %agent_id, "Client disconnected while seeding peers");
                                                break;
                                            }
                                        }
                                        Err(e) => {
                                            error!(
                                                agent_id = %agent_id,
                                                device_pub = %dev.public_key,
                                                error = %e,
                                                "Failed to acquire lease; sending PeerRemove"
                                            );
                                            let msg = AgentManager::peer_remove_message(
                                                &agent_id,
                                                &dev.public_key,
                                                Vec::new(),
                                            );
                                            let _ = tx.send(Ok(msg)).await;
                                        }
                                    }
                                } else {
                                    // Fallback for tests without lease manager: provide zeroed lease metadata
                                    warn!(
                                        agent_id = %agent_id,
                                        device_pub = %dev.public_key,
                                        "Lease manager unavailable during seed; emitting placeholder PeerAdd"
                                    );
                                    let placeholder = LeaseState {
                                        version: 0,
                                        nonce: Vec::new(),
                                    };
                                    let msg = AgentManager::peer_add_message(
                                        &agent_id,
                                        dev,
                                        &placeholder,
                                    );
                                    if tx.send(Ok(msg)).await.is_err() {
                                        warn!(agent_id = %agent_id, "Client disconnected while seeding peers");
                                        break;
                                    }
                                }
                            } else {
                                let lease_state = if let Some(ref lm) = lease_manager {
                                    match lm.current(&dev.id).await {
                                        Ok(Some(state)) => Some(state),
                                        Ok(None) => None,
                                        Err(err) => {
                                            warn!(
                                                agent_id = %agent_id,
                                                device_pub = %dev.public_key,
                                                error = %err,
                                                "Failed reading lease state during seed"
                                            );
                                            None
                                        }
                                    }
                                } else {
                                    None
                                };
                                let expected_nonce = lease_state
                                    .as_ref()
                                    .map(|state| state.nonce.clone())
                                    .unwrap_or_default();
                                info!(
                                    agent_id = %agent_id,
                                    device_pub = %dev.public_key,
                                    owner = ?owner,
                                    "Not owner during seed: sending PeerRemove"
                                );
                                if let Some(state) = lease_state {
                                    let update = AgentManager::lease_update_message(
                                        &agent_id,
                                        &dev.public_key,
                                        &state,
                                    );
                                    let _ = tx.send(Ok(update)).await;
                                }
                                let msg = AgentManager::peer_remove_message(
                                    &agent_id,
                                    &dev.public_key,
                                    expected_nonce,
                                );
                                if tx.send(Ok(msg)).await.is_err() {
                                    warn!(agent_id = %agent_id, "Client disconnected while seeding peers");
                                    break;
                                }
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
            let mut drift_interval = interval(Duration::from_secs(120)); // Drift cleanup every 2 minutes
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

                        let missed = health_counter_clone.fetch_add(1, Ordering::Relaxed) + 1;
                        if missed > MAX_MISSED_CHECKS {
                            error!(
                                agent_id = %agent_id,
                                missed_checks = missed,
                                "Agent failed health checks, removing connection"
                            );
                            break;
                        }
                    }

                    // Periodic drift cleanup: remove peers not owned by this relay
                    _ = drift_interval.tick() => {
                        if let Some(reg) = registry.as_ref() {
                            let devices = reg.list_all_devices().await;
                            for dev in devices {
                                let active = key_manager_clone.list_agents();
                                let owner = AgentManager::resolve_owner_for_device(
                                    &dev,
                                    &active,
                                )
                                .await;
                                if owner.as_deref() == Some(&agent_id) {
                                    if let Some(ref lm) = lease_manager {
                                        let cached = {
                                            let cache = lease_cache.read().await;
                                            cache.get(&dev.public_key).cloned()
                                        };
                                        let mut lease_outcome = None;
                                        if let Some(state) = cached {
                                            match lm.refresh(&dev.id, &state).await {
                                                Ok(true) => {
                                                    // refreshed successfully, nothing to send
                                                }
                                                Ok(false) => {
                                                    info!(agent_id = %agent_id, device_pub = %dev.public_key, "Lease refresh mismatch; rotating lease");
                                                    match lm.acquire(&dev.id).await {
                                                        Ok(outcome) => lease_outcome = Some(outcome),
                                                        Err(err) => warn!(agent_id = %agent_id, device_pub = %dev.public_key, error = %err, "Failed to reacquire lease during drift"),
                                                    }
                                                }
                                                Err(err) => {
                                                    warn!(agent_id = %agent_id, device_pub = %dev.public_key, error = %err, "Failed to refresh lease during drift; reacquiring");
                                                    match lm.acquire(&dev.id).await {
                                                        Ok(outcome) => lease_outcome = Some(outcome),
                                                        Err(err2) => warn!(agent_id = %agent_id, device_pub = %dev.public_key, error = %err2, "Failed to reacquire lease after refresh error"),
                                                    }
                                                }
                                            }
                                        } else {
                                            match lm.acquire(&dev.id).await {
                                                Ok(outcome) => lease_outcome = Some(outcome),
                                                Err(err) => warn!(agent_id = %agent_id, device_pub = %dev.public_key, error = %err, "Failed to acquire lease during drift"),
                                            }
                                        }

                                        if let Some(outcome) = lease_outcome {
                                            {
                                                let mut cache = lease_cache.write().await;
                                                cache.insert(dev.public_key.clone(), outcome.lease.clone());
                                            }
                                            let msg = AgentManager::peer_add_message(&agent_id, &dev, &outcome.lease);
                                            if tx.send(Ok(msg)).await.is_err() {
                                                warn!(agent_id = %agent_id, "Client disconnected while sending drift PeerAdd");
                                                break;
                                            }
                                        }
                                    }
                                } else {
                                    let lease_state = {
                                        let cached = {
                                            let cache = lease_cache.read().await;
                                            cache.get(&dev.public_key).cloned()
                                        };
                                        if let Some(state) = cached {
                                            Some(state)
                                        } else if let Some(ref lm) = lease_manager {
                                            match lm.current(&dev.id).await {
                                                Ok(Some(state)) => Some(state),
                                                Ok(None) => None,
                                                Err(err) => {
                                                    warn!(agent_id = %agent_id, device_pub = %dev.public_key, error = %err, "Failed to read lease during drift cleanup");
                                                    None
                                                }
                                            }
                                        } else {
                                            None
                                        }
                                    };
                                    let expected_nonce = lease_state
                                        .as_ref()
                                        .map(|state| state.nonce.clone())
                                        .unwrap_or_default();
                                    let msg = AgentManager::peer_remove_message(
                                        &agent_id,
                                        &dev.public_key,
                                        expected_nonce,
                                    );
                                    if let Some(state) = lease_state {
                                        let update = AgentManager::lease_update_message(
                                            &agent_id,
                                            &dev.public_key,
                                            &state,
                                        );
                                        let _ = tx.send(Ok(update)).await;
                                    }
                                    let _ = tx.send(Ok(msg)).await;
                                }
                            }
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
                                let active = key_manager_clone.list_agents();
                                let owner = AgentManager::resolve_owner_for_device(
                                    &dev,
                                    &active,
                                )
                                .await;
                                if owner.as_deref() == Some(&agent_id) {
                                    if let Some(ref lm) = lease_manager {
                                        match lm.acquire(&dev.id).await {
                                            Ok(outcome) => {
                                                {
                                                    let mut cache = lease_cache.write().await;
                                                    cache.insert(dev.public_key.clone(), outcome.lease.clone());
                                                }
                                                info!(agent_id = %agent_id, device_pub = %dev.public_key, lease_version = outcome.lease.version, "Ownership match on diff: sending PeerAdd with lease");
                                                let msg = AgentManager::peer_add_message(&agent_id, &dev, &outcome.lease);
                                                if tx.send(Ok(msg)).await.is_err() {
                                                    warn!(agent_id = %agent_id, "Client disconnected while sending device add");
                                                    break;
                                                }
                                            }
                                            Err(err) => {
                                                error!(agent_id = %agent_id, device_pub = %dev.public_key, error = %err, "Failed to acquire lease for added device; issuing PeerRemove");
                                                let msg = AgentManager::peer_remove_message(&agent_id, &dev.public_key, Vec::new());
                                                let _ = tx.send(Ok(msg)).await;
                                            }
                                        }
                                    } else {
                                        let placeholder = LeaseState { version: 0, nonce: Vec::new() };
                                        let msg = AgentManager::peer_add_message(&agent_id, &dev, &placeholder);
                                        if tx.send(Ok(msg)).await.is_err() {
                                            warn!(agent_id = %agent_id, "Client disconnected while sending device add");
                                            break;
                                        }
                                    }
                                } else {
                                    info!(agent_id = %agent_id, device_pub = %dev.public_key, owner = ?owner, "Not owner on diff: sending PeerRemove");
                                    let lease_state = {
                                        let cached = {
                                            let cache = lease_cache.read().await;
                                            cache.get(&dev.public_key).cloned()
                                        };
                                        if let Some(state) = cached {
                                            Some(state)
                                        } else if let Some(ref lm) = lease_manager {
                                            match lm.current(&dev.id).await {
                                                Ok(Some(state)) => Some(state),
                                                _ => None,
                                            }
                                        } else {
                                            None
                                        }
                                    };
                                    let expected_nonce = lease_state
                                        .as_ref()
                                        .map(|state| state.nonce.clone())
                                        .unwrap_or_default();
                                    if let Some(state) = lease_state {
                                        let update = AgentManager::lease_update_message(
                                            &agent_id,
                                            &dev.public_key,
                                            &state,
                                        );
                                        let _ = tx.send(Ok(update)).await;
                                    }
                                    let msg = AgentManager::peer_remove_message(&agent_id, &dev.public_key, expected_nonce);
                                    if tx.send(Ok(msg)).await.is_err() {
                                        warn!(agent_id = %agent_id, "Client disconnected while sending device add");
                                        break;
                                    }
                                }
                            }
                            RegistryDiff::Removed { public_key, device_id } => {
                                let cached = {
                                    let mut cache = lease_cache.write().await;
                                    cache.remove(&public_key)
                                };
                                if let Some(ref lm) = lease_manager {
                                    if let Some(state) = cached.clone() {
                                        if let Err(err) = lm.release(&device_id, &state).await {
                                            warn!(device_pub = %public_key, error = %err, "Failed to release lease for removed device");
                                        }
                                    } else if let Ok(Some(state)) = lm.current(&device_id).await {
                                        if let Err(err) = lm.release(&device_id, &state).await {
                                            warn!(device_pub = %public_key, error = %err, "Failed to release current lease for removed device");
                                        }
                                    }
                                }

                                let expected_nonce = cached.map(|state| state.nonce).unwrap_or_default();
                                let msg = AgentManager::peer_remove_message(&agent_id, &public_key, expected_nonce);
                                if tx.send(Ok(msg)).await.is_err() {
                                    warn!(agent_id = %agent_id, "Client disconnected while sending device remove");
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            // Clean up when connection ends
            warn!(
                agent_id = %agent_id,
                "Agent subscription ended, cleaning up connection"
            );
            key_manager_clone.remove_agent_keys(&agent_id);
            {
                let mut trackers = health_trackers.write().await;
                trackers.remove(&agent_id);
            }
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

    pub async fn record_health_response(
        &self,
        agent_id: &str,
        timestamp: i64,
        status: String,
    ) -> bool {
        let tracker = {
            let trackers = self.health_trackers.read().await;
            trackers.get(agent_id).cloned()
        };

        match tracker {
            Some(counter) => {
                counter.store(0, Ordering::Relaxed);
                self.key_manager.update_agent_activity(agent_id);
                debug!(
                    agent_id = %agent_id,
                    status = %status,
                    timestamp,
                    "Health response recorded"
                );
                true
            }
            None => {
                warn!(
                    agent_id = %agent_id,
                    "Health response received for unknown agent"
                );
                false
            }
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

    #[test]
    fn test_owner_for_is_deterministic() {
        let pubkey = "FxDknS+tXYeK478okCCqnbnA01W8P5n+nYEs3y9RelE=";
        let a = vec![
            "relay-a".to_string(),
            "relay-b".to_string(),
            "relay-c".to_string(),
        ];
        let b = vec![
            "relay-c".to_string(),
            "relay-b".to_string(),
            "relay-a".to_string(),
        ];
        let owner_a = AgentManager::owner_for(pubkey, &a).expect("owner");
        let owner_b = AgentManager::owner_for(pubkey, &b).expect("owner");
        assert_eq!(owner_a, owner_b, "Owner should be independent of order");
    }

    #[test]
    fn test_owner_for_changes_when_active_set_changes() {
        let pubkey = "FxDknS+tXYeK478okCCqnbnA01W8P5n+nYEs3y9RelE=";
        let active = vec![
            "relay-a".to_string(),
            "relay-b".to_string(),
            "relay-c".to_string(),
        ];
        let owner1 = AgentManager::owner_for(pubkey, &active).expect("owner");
        let reduced: Vec<String> = active.into_iter().filter(|id| id != &owner1).collect();
        let owner2 = AgentManager::owner_for(pubkey, &reduced).expect("owner after change");
        assert_ne!(
            owner1, owner2,
            "Owner should change when previous owner is removed"
        );
    }

    #[tokio::test]
    async fn test_record_health_response_resets_counter() {
        let manager = AgentManager::new_with_cleanup(false);
        let counter = std::sync::Arc::new(AtomicU32::new(2));
        {
            let mut trackers = manager.health_trackers.write().await;
            trackers.insert("agent-1".to_string(), counter.clone());
        }

        let accepted = manager
            .record_health_response("agent-1", 123, "ok".to_string())
            .await;
        assert!(accepted);
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_record_health_response_unknown_agent() {
        let manager = AgentManager::new_with_cleanup(false);
        let accepted = manager
            .record_health_response("ghost", 0, "ok".to_string())
            .await;
        assert!(!accepted);
    }
}

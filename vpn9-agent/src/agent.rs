use std::collections::{HashMap, HashSet, hash_map::Entry};
use std::fs;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tonic::transport::{Certificate, Channel, ClientTlsConfig};
use tonic::{Status, Streaming};
use tracing::{debug, error, info, warn};

use vpn9_core::control_plane::control_plane_client::ControlPlaneClient;
use vpn9_core::control_plane::{
    AgentSubscriptionMessage, AgentSubscriptionRequest, HealthResponse,
    agent_subscription_message::Message,
};

use tokio::sync::Mutex;
use tokio::time::MissedTickBehavior;

use crate::agent_id::AgentId;
use crate::runtime_security::RuntimeSecurity;
use crate::secure_system_info::{OsInfo, collect_os_info};
use crate::version::get_version;
use crate::wireguard_manager::{PeerSnapshot, WireGuardManager};

const DEFAULT_HANDSHAKE_STALE_SECS: u64 = 180;
const KEEPALIVE_STALE_MULTIPLIER: u64 = 3;
const HANDSHAKE_DETECT_INTERVAL_SECS: u64 = 5;

pub struct VPN9Agent {
    agent_id: AgentId,
    control_plane_url: String,
    agent_version: String,
    heartbeat_interval: Duration,
    runtime_security: RuntimeSecurity,
    wireguard_manager: Arc<WireGuardManager>,
    handshake_state: Arc<Mutex<HashMap<String, PeerState>>>,
}

#[derive(Clone, Debug, Default)]
struct PeerState {
    last_handshake: Option<SystemTime>,
    last_tx: u64,
    last_rx: u64,
    connected: bool,
}

#[derive(Debug)]
enum SessionAction {
    Reconnect,
    Shutdown { reason: String },
}

impl VPN9Agent {
    pub fn new(control_plane_url: String) -> Self {
        Self {
            agent_id: AgentId::derive(),
            control_plane_url,
            agent_version: get_version(),
            heartbeat_interval: Duration::from_secs(60),
            runtime_security: RuntimeSecurity::new(),
            wireguard_manager: Arc::new(WireGuardManager::new()),
            handshake_state: Arc::new(Mutex::new(HashMap::new())),
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

        let ca_cert_path = std::env::var("VPN9_TLS_CA_CERT_PATH").ok();
        let domain_override = std::env::var("VPN9_TLS_DOMAIN").ok();

        let tls_config =
            Self::build_tls_config(domain_override.as_deref(), ca_cert_path.as_deref())?;

        let channel = Channel::from_shared(self.control_plane_url.clone())?
            .tls_config(tls_config)?
            .connect()
            .await?;

        Ok(ControlPlaneClient::new(channel))
    }

    fn build_tls_config(
        domain_override: Option<&str>,
        ca_cert_path: Option<&str>,
    ) -> Result<ClientTlsConfig, Box<dyn std::error::Error>> {
        let domain_name = domain_override.unwrap_or("vpn9-control-plane");
        let mut tls_config = ClientTlsConfig::new().domain_name(domain_name);

        if let Some(ca_path) = ca_cert_path {
            info!("Using custom CA certificate from: {}", ca_path);
            let ca_cert = fs::read(ca_path)
                .map_err(|e| format!("Failed to read CA certificate file {ca_path}: {e}"))?;
            let ca_certificate = Certificate::from_pem(ca_cert);
            tls_config = tls_config.ca_certificate(ca_certificate);
        }

        Ok(tls_config)
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
                Ok(SessionAction::Reconnect) => {
                    info!("Control plane session ended; reconnecting soon");
                }
                Ok(SessionAction::Shutdown { reason }) => {
                    info!(%reason, "Control plane requested shutdown; stopping agent");
                    return Ok(());
                }
                Err(err) => {
                    error!(
                        ?err,
                        "Control plane session ended with error; reconnecting soon"
                    );
                }
            }

            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    async fn run_once(
        &self,
        os_info: &OsInfo,
    ) -> Result<SessionAction, Box<dyn std::error::Error>> {
        let mut client = self.create_control_plane_client().await?;
        let response_stream = self
            .subscribe_to_control_plane(&mut client, os_info)
            .await?;
        let health_client = Arc::new(Mutex::new(client.clone()));
        self.run_main_loop(response_stream, health_client).await
    }

    async fn subscribe_to_control_plane(
        &self,
        client: &mut ControlPlaneClient<Channel>,
        os_info: &OsInfo,
    ) -> Result<Streaming<AgentSubscriptionMessage>, Box<dyn std::error::Error>> {
        let request = tonic::Request::new(self.build_subscription_request(os_info));

        info!("Subscribing to control plane...");
        info!("Using agent_id={}", self.agent_id);
        let response = client.subscribe_agent(request).await?;

        info!("Subscription established with control plane");
        info!("Agent {} now streaming", self.agent_id);

        Ok(response.into_inner())
    }

    fn build_subscription_request(&self, os_info: &OsInfo) -> AgentSubscriptionRequest {
        AgentSubscriptionRequest {
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
        }
    }

    async fn run_main_loop(
        &self,
        mut response_stream: Streaming<AgentSubscriptionMessage>,
        health_client: Arc<Mutex<ControlPlaneClient<Channel>>>,
    ) -> Result<SessionAction, Box<dyn std::error::Error>> {
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

        let wg_manager = self.wireguard_manager.clone();
        let health_client = health_client;
        let mut heartbeat_interval = tokio::time::interval(self.heartbeat_interval);
        let mut handshake_interval =
            tokio::time::interval(Duration::from_secs(HANDSHAKE_DETECT_INTERVAL_SECS));

        heartbeat_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        handshake_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            let event = tokio::select! {
                message = response_stream.message() => AgentEvent::from_stream_result(message),
                _ = heartbeat_interval.tick() => AgentEvent::Heartbeat,
                _ = handshake_interval.tick() => AgentEvent::HandshakePoll,
            };

            match event {
                AgentEvent::ControlMessage(message) => {
                    if let Some(action) = self
                        .handle_control_message(message, &wg_manager, &health_client)
                        .await?
                    {
                        return Ok(action);
                    }
                }
                AgentEvent::StreamClosed => {
                    info!("Control plane subscription stream ended");
                    return Ok(SessionAction::Reconnect);
                }
                AgentEvent::StreamError(status) => {
                    error!(?status, "Control plane subscription stream error");
                    return Err(Box::new(status));
                }
                AgentEvent::Heartbeat => {
                    self.log_heartbeat(secure_status, wg_manager.as_ref());
                }
                AgentEvent::HandshakePoll => {
                    self.detect_new_handshakes(wg_manager.as_ref()).await;
                }
                AgentEvent::Empty => {}
            }
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

    pub fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    pub fn wireguard_manager(&self) -> Arc<WireGuardManager> {
        self.wireguard_manager.clone()
    }

    fn log_heartbeat(&self, secure_status: &str, wg_manager: &WireGuardManager) {
        let vpn_status = if wg_manager.is_configured() {
            "VPN ACTIVE"
        } else {
            "VPN INACTIVE"
        };

        debug!(
            "Agent heartbeat - version: {} ({}) - {}",
            self.agent_version, secure_status, vpn_status
        );
    }

    async fn handle_control_message(
        &self,
        message: Message,
        wg_manager: &Arc<WireGuardManager>,
        health_client: &Arc<Mutex<ControlPlaneClient<Channel>>>,
    ) -> Result<Option<SessionAction>, Box<dyn std::error::Error>> {
        match message {
            Message::AgentRegistration(registration) => {
                self.handle_agent_registration(registration, wg_manager);
                Ok(None)
            }
            Message::PeerAdd(peer_req) => {
                self.handle_peer_add(peer_req, wg_manager);
                Ok(None)
            }
            Message::PeerRemove(peer_rm) => {
                self.handle_peer_remove(peer_rm, wg_manager);
                Ok(None)
            }
            Message::HealthCheck(health_check) => {
                self.handle_health_check(health_check, health_client)
                    .await?;
                Ok(None)
            }
            Message::HealthResponse(health_response) => {
                self.handle_health_response(health_response);
                Ok(None)
            }
            Message::AgentDisconnect(disconnect) => {
                let action = self.handle_agent_disconnect(disconnect);
                Ok(Some(action))
            }
        }
    }

    fn handle_agent_registration(
        &self,
        registration: vpn9_core::control_plane::AgentRegistration,
        wg_manager: &Arc<WireGuardManager>,
    ) {
        if let Err(_err) = wg_manager.configure_from_registration(&registration) {
            // WireGuard manager logs detailed errors; keep loop alive
        }
    }

    fn handle_peer_add(
        &self,
        peer_req: vpn9_core::control_plane::PeerAdd,
        wg_manager: &Arc<WireGuardManager>,
    ) {
        if let Err(_err) = wg_manager.add_peer_from_request(&peer_req) {
            // WireGuard manager logs detailed errors; continue processing
        }
    }

    fn handle_peer_remove(
        &self,
        peer_rm: vpn9_core::control_plane::PeerRemove,
        wg_manager: &Arc<WireGuardManager>,
    ) {
        if let Err(_err) = wg_manager.remove_peer_from_request(&peer_rm) {
            // WireGuard manager logs detailed errors; continue processing
        }
    }

    async fn handle_health_check(
        &self,
        health_check: vpn9_core::control_plane::HealthCheck,
        health_client: &Arc<Mutex<ControlPlaneClient<Channel>>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug!(
            "💓 Health check received from control plane (timestamp: {}, agent_id={})",
            health_check.timestamp, health_check.agent_id
        );

        let response = HealthResponse {
            agent_id: health_check.agent_id.clone(),
            timestamp: health_check.timestamp,
            status: "ok".to_string(),
        };

        let mut client_guard = health_client.lock().await;
        if let Err(err) = client_guard.report_health(response).await {
            warn!("⚠️ Failed to report health to control plane: {}", err);
        } else {
            debug!("✅ Health response sent to control plane");
        }

        Ok(())
    }

    fn handle_health_response(&self, _health_response: vpn9_core::control_plane::HealthResponse) {
        debug!("💚 Health response received from control plane");
    }

    fn handle_agent_disconnect(
        &self,
        disconnect: vpn9_core::control_plane::AgentDisconnect,
    ) -> SessionAction {
        info!("🚪 Disconnect message received from control plane:");
        info!("  Agent ID: {}", disconnect.agent_id);
        info!("  Reason: {}", disconnect.reason);
        info!("Agent will now shut down gracefully...");
        SessionAction::Shutdown {
            reason: disconnect.reason,
        }
    }

    async fn detect_new_handshakes(&self, wg_manager: &WireGuardManager) {
        let snapshots = match wg_manager.peer_snapshots() {
            Ok(peers) => peers,
            Err(err) => {
                debug!(?err, "Failed to read WireGuard handshake state");
                return;
            }
        };

        self.update_peer_states(snapshots).await;
    }

    async fn update_peer_states(&self, snapshots: Vec<PeerSnapshot>) {
        let now = SystemTime::now();
        let mut state = self.handshake_state.lock().await;
        let mut seen = HashSet::new();

        for snapshot in snapshots {
            let PeerSnapshot {
                public_key,
                mut last_handshake,
                tx_bytes,
                rx_bytes,
                persistent_keepalive_interval,
            } = snapshot;

            last_handshake =
                last_handshake.and_then(|time| match time.duration_since(UNIX_EPOCH) {
                    Ok(duration) if duration.as_secs() > 0 || duration.subsec_nanos() > 0 => {
                        Some(time)
                    }
                    _ => None,
                });

            seen.insert(public_key.clone());

            let entry = match state.entry(public_key.clone()) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => entry.insert(PeerState::default()),
            };

            let previous_handshake = entry.last_handshake;
            let was_connected = entry.connected;
            let previous_tx = entry.last_tx;
            let previous_rx = entry.last_rx;

            let handshake_changed = previous_handshake != last_handshake;
            if handshake_changed {
                match last_handshake {
                    Some(time) => match time.duration_since(UNIX_EPOCH) {
                        Ok(duration) => info!(
                            peer = %public_key,
                            handshake_epoch = duration.as_secs(),
                            "🤝 WireGuard handshake observed"
                        ),
                        Err(_) => info!(
                            peer = %public_key,
                            "🤝 WireGuard handshake observed (pre-epoch timestamp)"
                        ),
                    },
                    None => debug!(peer = %public_key, "WireGuard handshake timestamp cleared"),
                }
            }

            let threshold = handshake_stale_threshold(persistent_keepalive_interval);
            let handshake_stale = match last_handshake {
                Some(time) => match now.duration_since(time) {
                    Ok(age) => age > threshold,
                    Err(_) => false,
                },
                None => true,
            };

            let bytes_advancing = previous_tx != tx_bytes || previous_rx != rx_bytes;
            let connected = last_handshake.is_some() && (!handshake_stale || bytes_advancing);

            if was_connected && !connected {
                let age_secs = last_handshake
                    .and_then(|time| now.duration_since(time).ok())
                    .map(|age| age.as_secs())
                    .unwrap_or(0);
                info!(
                    peer = %public_key,
                    handshake_age_secs = age_secs,
                    "⚠️ WireGuard peer handshake stale; marking disconnected"
                );
            }

            entry.last_handshake = last_handshake;
            entry.last_tx = tx_bytes;
            entry.last_rx = rx_bytes;
            entry.connected = connected;
        }

        state.retain(|key, _entry| {
            if !seen.contains(key) {
                info!(peer = %key, "⚠️ WireGuard peer removed from interface; marking disconnected");
                false
            } else {
                true
            }
        });
    }
}

#[derive(Debug)]
enum AgentEvent {
    ControlMessage(Message),
    Empty,
    StreamClosed,
    StreamError(Status),
    Heartbeat,
    HandshakePoll,
}

impl AgentEvent {
    fn from_stream_result(result: Result<Option<AgentSubscriptionMessage>, Status>) -> Self {
        match result {
            Ok(Some(wrapper)) => {
                if let Some(inner) = wrapper.message {
                    AgentEvent::ControlMessage(inner)
                } else {
                    AgentEvent::Empty
                }
            }
            Ok(None) => AgentEvent::StreamClosed,
            Err(status) => AgentEvent::StreamError(status),
        }
    }
}

fn handshake_stale_threshold(keepalive: Option<u16>) -> Duration {
    let keepalive_threshold = keepalive.filter(|interval| *interval > 0).map(|interval| {
        Duration::from_secs((interval as u64).saturating_mul(KEEPALIVE_STALE_MULTIPLIER))
    });

    keepalive_threshold
        .map(|duration| duration.max(Duration::from_secs(DEFAULT_HANDSHAKE_STALE_SECS)))
        .unwrap_or_else(|| Duration::from_secs(DEFAULT_HANDSHAKE_STALE_SECS))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wireguard_manager::PeerSnapshot;
    use std::net::IpAddr;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tonic::transport::Channel;
    use vpn9_core::control_plane::{
        AgentDisconnect, AgentSubscriptionMessage, HealthCheck, agent_subscription_message::Message,
    };

    fn sample_os_info() -> OsInfo {
        OsInfo {
            hostname: "test-host".into(),
            os_version: "test-os".into(),
            kernel_version: "test-kernel".into(),
            network_interfaces: vec![],
            public_ip: Some(IpAddr::from([10, 0, 0, 1])),
            cpu_count: 4,
            total_memory_mb: 8192,
        }
    }

    #[test]
    fn build_subscription_request_populates_fields() {
        let agent = VPN9Agent::new("https://localhost".into());
        let os_info = sample_os_info();

        let request = agent.build_subscription_request(&os_info);

        assert_eq!(request.hostname, "test-host");
        assert_eq!(request.os_version, "test-os");
        assert_eq!(request.kernel_version, "test-kernel");
        assert_eq!(request.public_ip, "10.0.0.1");
        assert_eq!(request.cpu_count, 4);
        assert_eq!(request.total_memory_mb, 8192);
        assert_eq!(request.agent_id, agent.agent_id().to_string());
    }

    #[test]
    fn agent_event_from_message_wraps_inner() {
        let message = AgentSubscriptionMessage {
            agent_id: "abc".into(),
            message: Some(Message::AgentDisconnect(AgentDisconnect {
                agent_id: "abc".into(),
                reason: "bye".into(),
            })),
        };

        match AgentEvent::from_stream_result(Ok(Some(message))) {
            AgentEvent::ControlMessage(Message::AgentDisconnect(disconnect)) => {
                assert_eq!(disconnect.reason, "bye");
            }
            other => panic!("unexpected event: {:?}", other),
        }
    }

    #[test]
    fn agent_event_from_stream_handles_empty_message() {
        let message = AgentSubscriptionMessage {
            agent_id: "abc".into(),
            message: None,
        };

        assert!(matches!(
            AgentEvent::from_stream_result(Ok(Some(message))),
            AgentEvent::Empty
        ));
    }

    #[test]
    fn agent_event_from_stream_handles_end_and_error() {
        assert!(matches!(
            AgentEvent::from_stream_result(Ok(None)),
            AgentEvent::StreamClosed
        ));
        assert!(matches!(
            AgentEvent::from_stream_result(Err(Status::internal("boom"))),
            AgentEvent::StreamError(_)
        ));
    }

    #[test]
    fn handle_agent_disconnect_returns_shutdown_action() {
        let agent = VPN9Agent::new("https://localhost".into());
        let action = agent.handle_agent_disconnect(AgentDisconnect {
            agent_id: "abc".into(),
            reason: "maintenance".into(),
        });

        match action {
            SessionAction::Shutdown { reason } => assert_eq!(reason, "maintenance"),
            SessionAction::Reconnect => panic!("expected shutdown"),
        }
    }

    #[tokio::test]
    async fn handle_health_check_returns_ok_even_on_client_error() {
        let agent = VPN9Agent::new("https://localhost".into());
        let channel = Channel::from_static("http://[::]:50051").connect_lazy();
        let client = ControlPlaneClient::new(channel);
        let health_client = Arc::new(Mutex::new(client));

        let check = HealthCheck {
            agent_id: "test-agent".into(),
            timestamp: 123,
        };

        let result = agent.handle_health_check(check, &health_client).await;

        assert!(result.is_ok());
    }

    fn make_snapshot(handshake: Option<SystemTime>, tx: u64, rx: u64) -> PeerSnapshot {
        PeerSnapshot {
            public_key: "peer".into(),
            last_handshake: handshake,
            tx_bytes: tx,
            rx_bytes: rx,
            persistent_keepalive_interval: Some(10),
        }
    }

    #[tokio::test]
    async fn update_peer_states_marks_disconnect_when_handshake_stale() {
        let agent = VPN9Agent::new("https://localhost".into());

        agent
            .update_peer_states(vec![make_snapshot(Some(SystemTime::now()), 100, 200)])
            .await;

        let stale_time = SystemTime::now() - Duration::from_secs(600);
        agent
            .update_peer_states(vec![make_snapshot(Some(stale_time), 100, 200)])
            .await;

        let state = agent.handshake_state.lock().await;
        let peer_state = state.get("peer").expect("peer state");
        assert!(!peer_state.connected);
    }

    #[tokio::test]
    async fn update_peer_states_removes_missing_peer() {
        let agent = VPN9Agent::new("https://localhost".into());

        agent
            .update_peer_states(vec![make_snapshot(Some(SystemTime::now()), 1, 1)])
            .await;
        agent.update_peer_states(Vec::new()).await;

        let state = agent.handshake_state.lock().await;
        assert!(state.is_empty());
    }

    #[tokio::test]
    async fn update_peer_states_treats_epoch_zero_as_missing() {
        let agent = VPN9Agent::new("https://localhost".into());

        agent
            .update_peer_states(vec![make_snapshot(Some(UNIX_EPOCH), 10, 20)])
            .await;

        let state = agent.handshake_state.lock().await;
        let peer_state = state.get("peer").expect("peer state");
        assert!(peer_state.last_handshake.is_none());
        assert!(!peer_state.connected);
    }
}

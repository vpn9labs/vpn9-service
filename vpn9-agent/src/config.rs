use std::time::Duration;

use crate::version::get_version;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub control_plane_url: String,
    pub agent_version: String,
    pub heartbeat_interval_secs: u64,
    pub max_retry_attempts: u32,
    pub retry_delay_secs: u64,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            control_plane_url: "http://[::1]:50051".to_string(),
            agent_version: get_version(),
            heartbeat_interval_secs: 60, // 1 minute
            max_retry_attempts: 3,
            retry_delay_secs: 5,
        }
    }
}

impl AgentConfig {
    pub fn heartbeat_interval(&self) -> Duration {
        Duration::from_secs(self.heartbeat_interval_secs)
    }

    pub fn retry_delay(&self) -> Duration {
        Duration::from_secs(self.retry_delay_secs)
    }

    pub fn load_from_env() -> Self {
        let mut config = Self::default();

        if let Ok(url) = std::env::var("VPN9_CONTROL_PLANE_URL") {
            config.control_plane_url = url;
        }

        if let Ok(version) = std::env::var("VPN9_AGENT_VERSION") {
            config.agent_version = version;
        }

        if let Ok(interval) = std::env::var("VPN9_HEARTBEAT_INTERVAL") {
            if let Ok(secs) = interval.parse::<u64>() {
                config.heartbeat_interval_secs = secs;
            }
        }

        if let Ok(attempts) = std::env::var("VPN9_MAX_RETRY_ATTEMPTS") {
            if let Ok(num) = attempts.parse::<u32>() {
                config.max_retry_attempts = num;
            }
        }

        if let Ok(delay) = std::env::var("VPN9_RETRY_DELAY") {
            if let Ok(secs) = delay.parse::<u64>() {
                config.retry_delay_secs = secs;
            }
        }

        config
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.control_plane_url.is_empty() {
            return Err("Control plane URL cannot be empty".to_string());
        }

        if self.agent_version.is_empty() {
            return Err("Agent version cannot be empty".to_string());
        }

        if self.heartbeat_interval_secs == 0 {
            return Err("Heartbeat interval must be greater than 0".to_string());
        }

        if self.max_retry_attempts == 0 {
            return Err("Max retry attempts must be greater than 0".to_string());
        }

        Ok(())
    }
}

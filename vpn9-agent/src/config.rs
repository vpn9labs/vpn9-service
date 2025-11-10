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

        if let Ok(interval) = std::env::var("VPN9_HEARTBEAT_INTERVAL")
            && let Ok(secs) = interval.parse::<u64>() {
                config.heartbeat_interval_secs = secs;
            }

        if let Ok(attempts) = std::env::var("VPN9_MAX_RETRY_ATTEMPTS")
            && let Ok(num) = attempts.parse::<u32>() {
                config.max_retry_attempts = num;
            }

        if let Ok(delay) = std::env::var("VPN9_RETRY_DELAY")
            && let Ok(secs) = delay.parse::<u64>() {
                config.retry_delay_secs = secs;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::{Mutex, MutexGuard, OnceLock};
    use std::time::Duration;

    static ENV_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

    fn env_lock() -> MutexGuard<'static, ()> {
        ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env mutex poisoned")
    }

    struct EnvGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = env::var(key).ok();
            unsafe {
                env::set_var(key, value);
            }
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => unsafe {
                    env::set_var(self.key, value);
                },
                None => unsafe {
                    env::remove_var(self.key);
                },
            }
        }
    }

    #[test]
    fn default_config_uses_current_version() {
        let config = AgentConfig::default();

        assert_eq!(config.control_plane_url, "http://[::1]:50051");
        assert_eq!(config.agent_version, get_version());
        assert_eq!(config.heartbeat_interval_secs, 60);
        assert_eq!(config.max_retry_attempts, 3);
        assert_eq!(config.retry_delay_secs, 5);
    }

    #[test]
    fn load_from_env_overrides_all_supported_fields() {
        let _lock = env_lock();
        let _url = EnvGuard::set("VPN9_CONTROL_PLANE_URL", "https://example");
        let _version = EnvGuard::set("VPN9_AGENT_VERSION", "1.2.3-test");
        let _interval = EnvGuard::set("VPN9_HEARTBEAT_INTERVAL", "15");
        let _attempts = EnvGuard::set("VPN9_MAX_RETRY_ATTEMPTS", "7");
        let _delay = EnvGuard::set("VPN9_RETRY_DELAY", "9");

        let config = AgentConfig::load_from_env();

        assert_eq!(config.control_plane_url, "https://example");
        assert_eq!(config.agent_version, "1.2.3-test");
        assert_eq!(config.heartbeat_interval_secs, 15);
        assert_eq!(config.max_retry_attempts, 7);
        assert_eq!(config.retry_delay_secs, 9);
    }

    #[test]
    fn load_from_env_ignores_invalid_numbers() {
        let _lock = env_lock();
        let _interval = EnvGuard::set("VPN9_HEARTBEAT_INTERVAL", "not-a-number");
        let _attempts = EnvGuard::set("VPN9_MAX_RETRY_ATTEMPTS", "NaN");
        let _delay = EnvGuard::set("VPN9_RETRY_DELAY", "");

        let config = AgentConfig::load_from_env();

        assert_eq!(config.heartbeat_interval_secs, 60);
        assert_eq!(config.max_retry_attempts, 3);
        assert_eq!(config.retry_delay_secs, 5);
    }

    #[test]
    fn heartbeat_interval_returns_duration_in_seconds() {
        let config = AgentConfig {
            heartbeat_interval_secs: 42,
            ..AgentConfig::default()
        };

        assert_eq!(config.heartbeat_interval(), Duration::from_secs(42));
    }

    #[test]
    fn retry_delay_returns_duration_in_seconds() {
        let config = AgentConfig {
            retry_delay_secs: 11,
            ..AgentConfig::default()
        };

        assert_eq!(config.retry_delay(), Duration::from_secs(11));
    }

    #[test]
    fn validate_rejects_empty_control_plane_url() {
        let config = AgentConfig {
            control_plane_url: String::new(),
            ..AgentConfig::default()
        };

        let err = config.validate().unwrap_err();
        assert_eq!(err, "Control plane URL cannot be empty");
    }

    #[test]
    fn validate_rejects_empty_agent_version() {
        let config = AgentConfig {
            agent_version: String::new(),
            ..AgentConfig::default()
        };

        let err = config.validate().unwrap_err();
        assert_eq!(err, "Agent version cannot be empty");
    }

    #[test]
    fn validate_rejects_zero_heartbeat_interval() {
        let config = AgentConfig {
            heartbeat_interval_secs: 0,
            ..AgentConfig::default()
        };

        let err = config.validate().unwrap_err();
        assert_eq!(err, "Heartbeat interval must be greater than 0");
    }

    #[test]
    fn validate_rejects_zero_retry_attempts() {
        let config = AgentConfig {
            max_retry_attempts: 0,
            ..AgentConfig::default()
        };

        let err = config.validate().unwrap_err();
        assert_eq!(err, "Max retry attempts must be greater than 0");
    }
}

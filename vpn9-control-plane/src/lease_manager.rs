use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as BASE64;
use rand::RngCore;
use rand::rngs::OsRng;
use redis::Script;
use redis::aio::ConnectionManager;

const LEASE_KEY_PREFIX: &str = "vpn9:lease:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseState {
    pub version: u64,
    pub nonce: Vec<u8>,
}

impl LeaseState {
    pub fn encode(&self) -> String {
        format!("{}:{}", self.version, BASE64.encode(&self.nonce))
    }

    pub fn decode(raw: &str) -> Option<Self> {
        let mut parts = raw.splitn(2, ':');
        let version = parts.next()?.parse::<u64>().ok()?;
        let nonce_b64 = parts.next()?;
        let nonce = BASE64.decode(nonce_b64).ok()?;
        Some(Self { version, nonce })
    }
}

#[derive(Debug, Clone)]
pub struct LeaseOutcome {
    pub lease: LeaseState,
    pub replaced: Option<LeaseState>,
}

#[derive(Debug, thiserror::Error)]
pub enum LeaseError {
    #[error("redis error: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("failed to parse lease payload")]
    Parse,
}

pub struct LeaseManager {
    conn: ConnectionManager,
    ttl: Duration,
}

impl LeaseManager {
    pub async fn new(
        redis_url: &str,
        ttl: Duration,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let client = redis::Client::open(redis_url)?;
        let conn = ConnectionManager::new(client).await?;
        Ok(Self { conn, ttl })
    }

    fn key(&self, device_id: &str) -> String {
        format!("{LEASE_KEY_PREFIX}{device_id}")
    }

    fn random_nonce() -> Vec<u8> {
        let mut bytes = vec![0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        bytes
    }

    pub async fn current(&self, device_id: &str) -> Result<Option<LeaseState>, LeaseError> {
        let mut conn = self.conn.clone();
        let key = self.key(device_id);
        let raw: Option<String> = redis::cmd("GET").arg(key).query_async(&mut conn).await?;
        match raw {
            Some(payload) => LeaseState::decode(&payload)
                .ok_or(LeaseError::Parse)
                .map(Some),
            None => Ok(None),
        }
    }

    pub async fn acquire(&self, device_id: &str) -> Result<LeaseOutcome, LeaseError> {
        let mut conn = self.conn.clone();
        let key = self.key(device_id);
        let new_nonce = Self::random_nonce();
        let new_nonce_b64 = BASE64.encode(&new_nonce);
        let ttl_secs = self.ttl.as_secs().max(1);
        let script = Script::new(
            r#"
            local key = KEYS[1]
            local ttl = tonumber(ARGV[1])
            local new_nonce = ARGV[2]

            local current = redis.call('GET', key)
            local current_version = 0
            local current_nonce = ''
            if current then
                local sep = string.find(current, ':', 1, true)
                if sep then
                    current_version = tonumber(string.sub(current, 1, sep - 1)) or 0
                    current_nonce = string.sub(current, sep + 1)
                end
            end

            local new_version = current_version + 1
            local new_value = tostring(new_version) .. ':' .. new_nonce
            redis.call('SET', key, new_value, 'EX', ttl)

            if current then
                return {tostring(new_version), tostring(current_version), current_nonce}
            else
                return {tostring(new_version), '', ''}
            end
        "#,
        );

        let result: Vec<String> = script
            .key(key)
            .arg(ttl_secs)
            .arg(&new_nonce_b64)
            .invoke_async(&mut conn)
            .await?;

        if result.len() != 3 {
            return Err(LeaseError::Parse);
        }

        let new_version = result[0].parse::<u64>().map_err(|_| LeaseError::Parse)?;
        let new_state = LeaseState {
            version: new_version,
            nonce: new_nonce,
        };

        let replaced = if !result[1].is_empty() && !result[2].is_empty() {
            let version = result[1].parse::<u64>().map_err(|_| LeaseError::Parse)?;
            let nonce = BASE64.decode(&result[2]).map_err(|_| LeaseError::Parse)?;
            Some(LeaseState { version, nonce })
        } else {
            None
        };

        Ok(LeaseOutcome {
            lease: new_state,
            replaced,
        })
    }

    pub async fn refresh(&self, device_id: &str, lease: &LeaseState) -> Result<bool, LeaseError> {
        let mut conn = self.conn.clone();
        let key = self.key(device_id);
        let payload = lease.encode();
        let ttl_secs = self.ttl.as_secs().max(1);
        let script = Script::new(
            r#"
            local key = KEYS[1]
            local ttl = tonumber(ARGV[1])
            local expected = ARGV[2]

            local current = redis.call('GET', key)
            if not current then
                return 0
            end

            if current ~= expected then
                return 0
            end

            redis.call('SET', key, expected, 'EX', ttl)
            return 1
        "#,
        );

        let refreshed: i64 = script
            .key(key)
            .arg(ttl_secs)
            .arg(&payload)
            .invoke_async(&mut conn)
            .await?;
        Ok(refreshed == 1)
    }

    pub async fn release(&self, device_id: &str, lease: &LeaseState) -> Result<bool, LeaseError> {
        let mut conn = self.conn.clone();
        let key = self.key(device_id);
        let payload = lease.encode();
        let script = Script::new(
            r#"
            local key = KEYS[1]
            local expected = ARGV[1]

            local current = redis.call('GET', key)
            if not current then
                return 0
            end

            if current ~= expected then
                return 0
            end

            redis.call('DEL', key)
            return 1
        "#,
        );

        let deleted: i64 = script
            .key(key)
            .arg(&payload)
            .invoke_async(&mut conn)
            .await?;
        Ok(deleted == 1)
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let lease = LeaseState {
            version: 42,
            nonce: vec![1, 2, 3, 4, 5],
        };
        let encoded = lease.encode();
        let decoded = LeaseState::decode(&encoded).expect("decode");
        assert_eq!(lease, decoded);
    }

    #[test]
    fn random_nonce_length_is_16_bytes() {
        let a = LeaseManager::random_nonce();
        let b = LeaseManager::random_nonce();
        assert_eq!(a.len(), 16);
        assert_eq!(b.len(), 16);
        // Extremely low probability of equality; ensures RNG hooked up.
        assert_ne!(a, b, "independent nonce samples should differ");
    }

    #[test]
    fn decode_rejects_malformed_payloads() {
        assert!(LeaseState::decode("not-a-valid-lease").is_none());
        assert!(LeaseState::decode("1:not_base64").is_none());
    }
}

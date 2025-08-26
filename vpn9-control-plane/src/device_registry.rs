use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use redis::aio::ConnectionManager;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone)]
pub struct DeviceRecord {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub public_key: String,
    pub ipv4: String,
    pub ipv6: String,
    pub allowed_ips: Vec<String>,
}

impl DeviceRecord {
    fn from_map(mut m: HashMap<String, String>) -> Option<Self> {
        let id = m.remove("id");
        let user_id = m.remove("user_id");
        let name = m.remove("name");
        let public_key = m.remove("public_key");
        let ipv4 = m.remove("ipv4");
        let ipv6 = m.remove("ipv6");
        let allowed_ips_raw = m.remove("allowed_ips");

        match (id, user_id, name, public_key, ipv4, ipv6, allowed_ips_raw) {
            (
                Some(id),
                Some(user_id),
                Some(name),
                Some(public_key),
                Some(ipv4),
                Some(ipv6),
                Some(allowed_ips_raw),
            ) => {
                let allowed_ips = allowed_ips_raw
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>();

                Some(Self {
                    id,
                    user_id,
                    name,
                    public_key,
                    ipv4,
                    ipv6,
                    allowed_ips,
                })
            }
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct DeviceRegistry {
    conn: ConnectionManager,
    // In-memory indexes
    active_ids: Arc<RwLock<HashSet<String>>>,
    by_id: Arc<RwLock<HashMap<String, DeviceRecord>>>,
    by_pubkey: Arc<RwLock<HashMap<String, String>>>, // pubkey -> device_id
}

impl DeviceRegistry {
    pub async fn new(
        redis_url: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let client = redis::Client::open(redis_url)?;
        let conn = redis::aio::ConnectionManager::new(client).await?;
        Ok(Self {
            conn,
            active_ids: Arc::new(RwLock::new(HashSet::new())),
            by_id: Arc::new(RwLock::new(HashMap::new())),
            by_pubkey: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn full_sync(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let active_ids = self.fetch_active_ids().await?;
        let devices = self.fetch_devices_bulk(&active_ids).await?;

        let mut by_id = HashMap::new();
        let mut by_pubkey = HashMap::new();

        for (id, rec_opt) in devices.into_iter() {
            match rec_opt {
                Some(rec) => {
                    by_pubkey.insert(rec.public_key.clone(), rec.id.clone());
                    by_id.insert(id, rec);
                }
                None => {
                    warn!(device_id = %id, "Active device missing or incomplete hash; deferring");
                }
            }
        }

        {
            let mut ids_lock = self.active_ids.write().await;
            *ids_lock = active_ids;
        }
        {
            let mut by_id_lock = self.by_id.write().await;
            *by_id_lock = by_id;
        }
        {
            let mut by_pk_lock = self.by_pubkey.write().await;
            *by_pk_lock = by_pubkey;
        }

        info!(
            active_count = self.active_ids.read().await.len(),
            loaded_count = self.by_id.read().await.len(),
            "Device registry full sync complete"
        );
        Ok(())
    }

    pub fn start_polling(self: Arc<Self>, interval_secs: u64) {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            // Trigger immediately after spawn
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if let Err(e) = self.incremental_refresh().await {
                    let err_msg = e.to_string();
                    error!(error = %err_msg, "Device registry incremental refresh failed");
                    // Backoff: wait a bit before retry
                    tokio::time::sleep(std::time::Duration::from_secs(2 * interval_secs)).await;
                }
            }
        });
    }

    async fn incremental_refresh(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let new_active = self.fetch_active_ids().await?;
        let old_active = self.active_ids.read().await.clone();

        let added: HashSet<_> = new_active.difference(&old_active).cloned().collect();
        let removed: HashSet<_> = old_active.difference(&new_active).cloned().collect();

        if !added.is_empty() || !removed.is_empty() {
            info!(
                added = added.len(),
                removed = removed.len(),
                "Active set changed"
            );
        } else {
            debug!("Active set unchanged");
        }

        // Fetch added devices' hashes in bulk
        if !added.is_empty() {
            let fetched = self.fetch_devices_bulk(&added).await?;
            let mut by_id_lock = self.by_id.write().await;
            let mut by_pk_lock = self.by_pubkey.write().await;
            for (id, rec_opt) in fetched.into_iter() {
                match rec_opt {
                    Some(rec) => {
                        by_pk_lock.insert(rec.public_key.clone(), rec.id.clone());
                        by_id_lock.insert(id, rec);
                    }
                    None => {
                        warn!(device_id = %id, "Active device missing or incomplete hash during refresh")
                    }
                }
            }
        }

        // Remove deactivated devices
        if !removed.is_empty() {
            let mut by_id_lock = self.by_id.write().await;
            let mut by_pk_lock = self.by_pubkey.write().await;
            for id in &removed {
                if let Some(rec) = by_id_lock.remove(id) {
                    by_pk_lock.remove(&rec.public_key);
                }
            }
        }

        // Update active set snapshot
        {
            let mut ids_lock = self.active_ids.write().await;
            *ids_lock = new_active;
        }

        Ok(())
    }

    async fn fetch_active_ids(
        &self,
    ) -> Result<HashSet<String>, Box<dyn std::error::Error + Send + Sync>> {
        let mut conn = self.conn.clone();
        let key = "vpn9:devices:active";

        // Use SSCAN to avoid loading very large sets at once
        let mut cursor: u64 = 0;
        let mut out: HashSet<String> = HashSet::new();
        loop {
            let (next, chunk): (u64, Vec<String>) = redis::cmd("SSCAN")
                .arg(key)
                .arg(cursor)
                .arg("COUNT")
                .arg(1000)
                .query_async(&mut conn)
                .await?;
            for id in chunk {
                out.insert(id);
            }
            if next == 0 {
                break;
            }
            cursor = next;
        }
        Ok(out)
    }

    async fn fetch_devices_bulk(
        &self,
        ids: &HashSet<String>,
    ) -> Result<HashMap<String, Option<DeviceRecord>>, Box<dyn std::error::Error + Send + Sync>> {
        use redis::FromRedisValue;
        let mut conn = self.conn.clone();

        let mut result: HashMap<String, Option<DeviceRecord>> = HashMap::new();
        if ids.is_empty() {
            return Ok(result);
        }

        // Chunk to avoid overly large responses
        let mut ids_vec: Vec<String> = ids.iter().cloned().collect();
        ids_vec.sort();
        for chunk in ids_vec.chunks(200) {
            let mut pipe = redis::pipe();
            pipe.atomic();
            let mut keys = Vec::with_capacity(chunk.len());
            for id in chunk {
                let key = format!("vpn9:device:{}", id);
                keys.push((id.clone(), key.clone()));
                pipe.cmd("HGETALL").arg(key);
            }

            let values: Vec<redis::Value> = pipe.query_async(&mut conn).await?;

            for (i, val) in values.into_iter().enumerate() {
                let (id, _key) = &keys[i];
                // Try to convert to HashMap<String, String>
                match HashMap::<String, String>::from_redis_value(&val) {
                    Ok(map) => {
                        if map.is_empty() {
                            result.insert(id.clone(), None);
                        } else if let Some(rec) = DeviceRecord::from_map(map) {
                            result.insert(id.clone(), Some(rec));
                        } else {
                            warn!(device_id = %id, "Incomplete device hash; skipping");
                            result.insert(id.clone(), None);
                        }
                    }
                    Err(_) => {
                        warn!(device_id = %id, "Failed to parse device hash");
                        result.insert(id.clone(), None);
                    }
                }
            }
        }

        Ok(result)
    }

    pub async fn is_active(&self, device_id: &str) -> bool {
        self.active_ids.read().await.contains(device_id)
    }

    pub async fn get_by_id(&self, device_id: &str) -> Option<DeviceRecord> {
        self.by_id.read().await.get(device_id).cloned()
    }

    pub async fn get_by_pubkey(&self, public_key: &str) -> Option<DeviceRecord> {
        let id = self.by_pubkey.read().await.get(public_key).cloned()?;
        self.get_by_id(&id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_parse_device_record() {
        let mut m = HashMap::new();
        m.insert("id".to_string(), "dev-1".to_string());
        m.insert("user_id".to_string(), "user-1".to_string());
        m.insert("name".to_string(), "My Device".to_string());
        m.insert("public_key".to_string(), "pk-abc".to_string());
        m.insert("ipv4".to_string(), "10.0.0.2".to_string());
        m.insert("ipv6".to_string(), "fd00::2".to_string());
        m.insert(
            "allowed_ips".to_string(),
            "10.0.0.2/32, fd00::2/128".to_string(),
        );

        let rec = DeviceRecord::from_map(m).expect("should parse");
        assert_eq!(rec.id, "dev-1");
        assert_eq!(rec.public_key, "pk-abc");
        assert_eq!(rec.allowed_ips, vec!["10.0.0.2/32", "fd00::2/128"]);
    }
}

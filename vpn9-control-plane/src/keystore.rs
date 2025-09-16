use std::env;

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use redis::aio::ConnectionManager;
use strong_box::{StaticStrongBox, StemStrongBox, StrongBox};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

#[derive(Clone)]
pub struct StrongBoxKeystore {
    root: StemStrongBox,
    conn: ConnectionManager,
}

impl StrongBoxKeystore {
    pub async fn from_env(
        redis_url: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let current_key_b64 =
            env::var("VPN9_SB_CURRENT_KEY").map_err(|_| "VPN9_SB_CURRENT_KEY not set")?;
        let current_key = decode_key32(&current_key_b64)?;

        let prev_keys: Vec<[u8; 32]> = env::var("VPN9_SB_PREV_KEYS")
            .ok()
            .map(|s| {
                s.split(',')
                    .filter(|t| !t.trim().is_empty())
                    .map(|t| decode_key32(t.trim()))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();

        // Root stem: decrypt set includes current + any previous
        // Build decryption key set: previous + current
        let mut dec_keys: Vec<Box<[u8; 32]>> = prev_keys.into_iter().map(Box::new).collect();
        dec_keys.push(Box::new(current_key));
        let root = StemStrongBox::new(Box::new(current_key), dec_keys);

        let client = redis::Client::open(redis_url)?;
        let conn = ConnectionManager::new(client).await?;
        Ok(Self { root, conn })
    }

    fn derive_agent_box(&self, agent_id: &str) -> StaticStrongBox {
        let ks = self.root.derive_stem("keystore");
        let wg = ks.derive_stem("wg");
        let relays = wg.derive_stem("relays");
        relays.derive_static(agent_id)
    }

    /// Get existing keypair for agent or create, encrypt, and store a new one. Returns (pub_b64, priv_b64).
    pub async fn get_or_create_and_decrypt(
        &self,
        agent_id: &str,
    ) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
        let key = format!("vpn9:relay:{agent_id}");
        {
            let mut pipe = redis::pipe();
            pipe.atomic();
            pipe.hget(&key, "wg_public_key");
            pipe.hget(&key, "wg_private_key_enc");
            let (pub_opt, ct_opt): (Option<String>, Option<String>) =
                pipe.query_async(&mut self.conn.clone()).await?;
            if let (Some(p), Some(c)) = (pub_opt, ct_opt) {
                let priv_b64 = self.decrypt_to_b64(agent_id, &c)?;
                return Ok((p, priv_b64));
            }
        }

        // Not present: generate
        let secret = StaticSecret::random();
        let public = PublicKey::from(&secret);
        let priv_bytes = secret.to_bytes();
        let pub_bytes = public.to_bytes();
        let pub_b64 = B64.encode(pub_bytes);

        let agent_box = self.derive_agent_box(agent_id);
        let mut priv_vec = priv_bytes.to_vec();
        let ciphertext = agent_box.encrypt(&priv_vec, agent_id)?;
        priv_vec.zeroize();
        let ct_b64 = B64.encode(ciphertext);

        let created_at = chrono::Utc::now().to_rfc3339();

        // Try to claim by setting pubkey if absent; then set others
        let set: i64 = redis::cmd("HSETNX")
            .arg(&key)
            .arg("wg_public_key")
            .arg(&pub_b64)
            .query_async(&mut self.conn.clone())
            .await?;
        if set == 1 {
            // We won the race; write rest
            let _: () = redis::cmd("HSET")
                .arg(&key)
                .arg("wg_private_key_enc")
                .arg(&ct_b64)
                .arg("created_at")
                .arg(&created_at)
                .arg("updated_at")
                .arg(&created_at)
                .query_async(&mut self.conn.clone())
                .await?;
            // return freshly generated plaintext
            let priv_b64 = B64.encode(priv_bytes);
            Ok((pub_b64, priv_b64))
        } else {
            // Lost race; load and decrypt
            let (p, c): (String, String) = redis::pipe()
                .cmd("HMGET")
                .arg(&key)
                .arg("wg_public_key")
                .arg("wg_private_key_enc")
                .query_async(&mut self.conn.clone())
                .await
                .map(|(p, c): (Option<String>, Option<String>)| (p.unwrap(), c.unwrap()))?;
            let priv_b64 = self.decrypt_to_b64(agent_id, &c)?;
            Ok((p, priv_b64))
        }
    }

    fn decrypt_to_b64(
        &self,
        agent_id: &str,
        ct_b64: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let agent_box = self.derive_agent_box(agent_id);
        let ct = B64.decode(ct_b64)?;
        let pt = agent_box.decrypt(&ct, agent_id)?; // Vec<u8>
        Ok(B64.encode(pt))
    }
}

fn decode_key32(b64: &str) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let v = base64::engine::general_purpose::STANDARD.decode(b64)?;
    if v.len() != 32 {
        return Err("invalid key size".into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

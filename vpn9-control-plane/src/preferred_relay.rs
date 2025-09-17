use std::num::NonZeroU32;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use openssl::symm::{Cipher, decrypt};
use ring::{hmac, pbkdf2};
use thiserror::Error;

const PREFERRED_RELAY_SALT: &str = "device_registry:preferred_relay:v1";
const PBKDF2_ITERATIONS: u32 = 1 << 16;

#[derive(Debug, Error)]
pub enum PreferredRelayError {
    #[error("missing digest separator")]
    MissingDigest,
    #[error("invalid digest hex")]
    InvalidDigest,
    #[error("hmac verification failed")]
    InvalidSignature,
    #[error("invalid envelope encoding")]
    InvalidEnvelope,
    #[error("invalid cipher payload")]
    InvalidCipherText,
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("utf8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("openssl error: {0}")]
    OpenSsl(#[from] openssl::error::ErrorStack),
    #[error("marshal decode error")]
    Marshal,
}

pub struct PreferredRelayDecryptor {
    key: [u8; 32],
    hmac_key: hmac::Key,
}

impl PreferredRelayDecryptor {
    pub fn new(secret: &str) -> Result<Self, PreferredRelayError> {
        let mut key = [0u8; 32];
        let iterations = NonZeroU32::new(PBKDF2_ITERATIONS).expect("iterations nonzero");
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA1,
            iterations,
            PREFERRED_RELAY_SALT.as_bytes(),
            secret.as_bytes(),
            &mut key,
        );
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &key);
        Ok(Self { key, hmac_key })
    }

    pub fn decrypt(&self, payload: &str) -> Result<String, PreferredRelayError> {
        let (encoded, digest_hex) = payload
            .split_once("--")
            .ok_or(PreferredRelayError::MissingDigest)?;

        let digest_bytes =
            decode_hex(digest_hex).map_err(|_| PreferredRelayError::InvalidDigest)?;
        hmac::verify(&self.hmac_key, encoded.as_bytes(), &digest_bytes)
            .map_err(|_| PreferredRelayError::InvalidSignature)?;

        let envelope_bytes = BASE64.decode(encoded)?;
        let envelope = String::from_utf8(envelope_bytes)?;

        let (cipher_b64, iv_b64) = envelope
            .split_once("--")
            .ok_or(PreferredRelayError::InvalidEnvelope)?;
        let cipher_bytes = BASE64.decode(cipher_b64)?;
        let iv_bytes = BASE64.decode(iv_b64)?;

        let plain = decrypt(
            Cipher::aes_256_cbc(),
            &self.key,
            Some(&iv_bytes),
            &cipher_bytes,
        )?;
        parse_ruby_string(&plain).ok_or(PreferredRelayError::Marshal)
    }
}

fn decode_hex(input: &str) -> Result<Vec<u8>, ()> {
    if input.len() % 2 != 0 {
        return Err(());
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    for idx in (0..bytes.len()).step_by(2) {
        let hi = from_hex_digit(bytes[idx])?;
        let lo = from_hex_digit(bytes[idx + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn from_hex_digit(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(10 + (b - b'a')),
        b'A'..=b'F' => Ok(10 + (b - b'A')),
        _ => Err(()),
    }
}

fn parse_ruby_string(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 5 {
        return None;
    }
    if bytes[0] != 0x04 || bytes[1] != 0x08 {
        return None;
    }
    let mut idx = 2;
    if bytes[idx] == b'I' {
        idx += 1;
    }
    if idx >= bytes.len() || bytes[idx] != b'"' {
        return None;
    }
    idx += 1;
    let (len, consumed) = decode_ruby_fixnum(&bytes[idx..])?;
    idx += consumed;
    if bytes.len() < idx + len {
        return None;
    }
    let value_bytes = &bytes[idx..idx + len];
    String::from_utf8(value_bytes.to_vec()).ok()
}

fn decode_ruby_fixnum(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.first()? as i8;
    if first == 0 {
        return Some((0, 1));
    }
    if (1..=4).contains(&first) {
        let count = first as usize;
        if bytes.len() < 1 + count {
            return None;
        }
        let mut value = 0i64;
        for i in 0..count {
            value |= (bytes[1 + i] as i64) << (8 * i);
        }
        return Some((value as usize, 1 + count));
    }
    if (-4..=-1).contains(&first) {
        let count = (-first) as usize;
        if bytes.len() < 1 + count {
            return None;
        }
        let mut value: i64 = -1;
        for i in 0..count {
            let shift = 8 * i;
            value &= !(0xFF << shift);
            value |= (bytes[1 + i] as i64) << shift;
        }
        return Some((value as isize as usize, 1 + count));
    }
    let value = (first as i64) - 5;
    if value < 0 {
        None
    } else {
        Some((value as usize, 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "secret";
    const SAMPLE_PAYLOAD: &str = "WVY2bVVHMm5ZOExQbGRTRGw1Syt2Vm9kZ3RJM0FsVDBmQ0dETVFQMFJIOD0tLWsxK1FDK0liWTQrbm1xT3p1Y2ZpV2c9PQ==--70a0b8ac37f4c1df61c7b0ec64ada6eb2f876788";

    #[test]
    fn decrypts_portal_payload() {
        let decryptor = PreferredRelayDecryptor::new(SECRET).expect("decryptor");
        let relay = decryptor.decrypt(SAMPLE_PAYLOAD).expect("relay");
        assert_eq!(relay, "relay-nyc-1");
    }

    #[test]
    fn rejects_tampered_signature() {
        let decryptor = PreferredRelayDecryptor::new(SECRET).expect("decryptor");
        let mut tampered = SAMPLE_PAYLOAD.to_owned();
        // Flip the final hex character to keep format but alter signature.
        tampered.pop();
        tampered.push('0');
        let err = decryptor.decrypt(&tampered).expect_err("should fail");
        assert!(matches!(
            err,
            PreferredRelayError::InvalidSignature | PreferredRelayError::InvalidDigest
        ));
    }

    #[test]
    fn parse_ruby_string_handles_simple_payload() {
        // Marshal.dump("test") => 0x04 0x08 0x49 0x22 0x09 't' 'e' 's' 't' 0x06 0x3a 0x06 0x45 0x54
        let data = [
            0x04, 0x08, 0x49, 0x22, 0x09, b't', b'e', b's', b't', 0x06, 0x3a, 0x06, 0x45, 0x54,
        ];
        let parsed = parse_ruby_string(&data).expect("parse");
        assert_eq!(parsed, "test");
    }
}

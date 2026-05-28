//! Key management: derivation, storage, lookup, and entitlement parsing.
//!
//! Ported from McCrypt/Keys.cs.
//! Handles:
//! - User key derivation (XOR of UserId and DeviceId in UTF-16LE)
//! - Entitlement key derivation (XOR of version key and padded title account ID)
//! - Content key derivation (XOR + decimation by factor of 2)
//! - Reading `.ent` entitlement files (versioned JSON with Mojang's wrapper)
//! - Reading `options.txt` for `last_minecraft_id` / `last_title_account_id`
//! - Reading/writing `keys.db` (plaintext `friendlyId=contentKey` lines)

use crate::crypto;
use crate::utils;
#[cfg(feature = "native")]
use std::path::Path;

/// A stored content key entry.
#[derive(Debug, Clone)]
struct Content {
    friendly_id: String,
    content_key: Vec<u8>,
}

/// Serializable key entry for JSON export.
#[derive(Debug, Clone, serde::Serialize)]
pub struct KeysJsonEntry {
    pub id: String,
    #[serde(rename = "contentKey")]
    pub content_key: String,
}

/// The global key store.
#[derive(Debug)]
pub struct Keys {
    /// In-memory key lookup.
    content_list: Vec<Content>,
    /// Path to keys.db file on disk (empty = not syncing).
    pub key_db_file: String,
    /// Random generator for key generation.
    rng: fastrand::Rng,

    // State from options.txt / entitlements
    pub last_title_account_id: String,
    pub last_minecraft_id: String,
    last_device_id: String,
}

impl Keys {
    /// Create a new empty key store.
    pub fn new() -> Self {
        Self {
            content_list: Vec::new(),
            key_db_file: String::new(),
            rng: fastrand::Rng::new(),
            last_title_account_id: String::new(),
            last_minecraft_id: String::new(),
            last_device_id: String::new(),
        }
    }

    /// Generate a random 32-character alphanumeric key.
    pub fn generate_key(&mut self) -> String {
        let allowed = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        let mut key = String::with_capacity(32);
        for _ in 0..32 {
            let idx = self.rng.usize(0..allowed.len());
            key.push(allowed[idx] as char);
        }
        key
    }

    // --- Key derivation ---

    /// Derive user key by XOR of UserId and DeviceId in UTF-16LE.
    fn derive_user_key(user_id: &str, device_id: &str) -> Vec<u8> {
        let user_bytes = to_utf16le(user_id);
        let device_bytes = to_utf16le(device_id);
        let klen = user_bytes.len().min(device_bytes.len());
        let mut key = Vec::with_capacity(klen);
        for i in 0..klen {
            key.push(user_bytes[i] ^ device_bytes[i]);
        }
        key
    }

    /// Derive entitlement key by XOR of version key and padded title account ID.
    fn derive_ent_key(version_key: &[u8], title_account_id: &[u8]) -> Vec<u8> {
        let klen = version_key.len().min(title_account_id.len());
        let mut key = version_key.to_vec();
        for i in 0..klen {
            key[i] ^= title_account_id[i];
        }
        key
    }

    /// Derive content key: XOR user_key and content_key, then decimate by 2.
    fn derive_content_key(user_key: &[u8], content_key: &[u8]) -> Vec<u8> {
        let klen = user_key.len().min(content_key.len());
        let mut xored = Vec::with_capacity(klen);
        for i in 0..klen {
            xored.push(user_key[i] ^ content_key[i]);
        }
        let cklen = klen / 2;
        let mut result = Vec::with_capacity(cklen);
        for i in (0..klen).step_by(2) {
            result.push(xored[i]);
        }
        result
    }

    // --- Key storage ---

    /// Add a key to the store. Skips if friendly_id already exists.
    /// If `add_to_key_cache` and `key_db_file` is set, appends to disk.
    pub fn add_key(&mut self, friendly_id: &str, content_key: &[u8], add_to_key_cache: bool) {
        if self.lookup_key(friendly_id).is_some() {
            return;
        }

        #[cfg(feature = "native")]
        if add_to_key_cache && !self.key_db_file.is_empty() {
            let entry = format!(
                "{}={}\n",
                friendly_id,
                String::from_utf8_lossy(content_key)
            );
            let _ = std::fs::write(&self.key_db_file, entry.as_bytes());
        }

        self.content_list.push(Content {
            friendly_id: friendly_id.to_string(),
            content_key: content_key.to_vec(),
        });
    }

    /// Look up a content key by friendly ID (pack UUID).
    pub fn lookup_key(&self, friendly_id: &str) -> Option<&[u8]> {
        self.content_list
            .iter()
            .find(|c| c.friendly_id == friendly_id)
            .map(|c| c.content_key.as_slice())
    }

    /// Export all keys (except the default skin key) as JSON array.
    pub fn export_keys_json(&self) -> String {
        let default_key = "s5s5ejuDru4uchuF2drUFuthaspAbepE";
        let entries: Vec<KeysJsonEntry> = self
            .content_list
            .iter()
            .filter(|c| String::from_utf8_lossy(&c.content_key) != default_key)
            .map(|c| KeysJsonEntry {
                id: c.friendly_id.clone(),
                content_key: String::from_utf8_lossy(&c.content_key).to_string(),
            })
            .collect();
        serde_json::to_string(&entries).unwrap_or_default()
    }

    // --- Entitlement handling ---

    /// Handle entitlements from a receipt JSON.
    fn handle_entitlements(&mut self, entitlements: &[serde_json::Value], user_key: &[u8]) {
        for ent in entitlements {
            let friendly_id = ent["FriendlyId"]
                .as_str()
                .or_else(|| ent["PackId"].as_str())
                .map(String::from);

            let friendly_id = match friendly_id {
                Some(id) => id,
                None => continue,
            };

            let content_key_b64 = match ent["ContentKey"].as_str() {
                Some(k) => k,
                None => continue,
            };

            let content_key = match utils::force_decode_base64(content_key_b64) {
                Some(k) => k,
                None => continue,
            };

            let real_content_key = Self::derive_content_key(user_key, &content_key);
            self.add_key(&friendly_id, &real_content_key, true);
        }
    }

    /// Read inner receipt data (EntityId, DeviceId, Entitlements).
    fn read_inner_receipt(&mut self, rec_data: &serde_json::Value) {
        let user_id = match rec_data["EntityId"].as_str() {
            Some(id) => id,
            None => return,
        };

        let device_id = rec_data["ReceiptData"]["DeviceId"]
            .as_str()
            .filter(|d| !d.is_empty())
            .unwrap_or(&self.last_device_id)
            .to_string();

        if device_id.is_empty() {
            return;
        }

        self.last_device_id = device_id.clone();
        let user_key = Self::derive_user_key(user_id, &device_id);

        let entitlements = if let Some(ents) = rec_data["Entitlements"].as_array() {
            ents.clone()
        } else if let Some(ents) = rec_data["EntitlementReceipts"].as_array() {
            ents.clone()
        } else {
            return;
        };

        self.handle_entitlements(&entitlements, &user_key);
    }

    /// Read a single receipt (base64-decoded JSON).
    fn read_receipt(&mut self, receipt_data: &str) {
        let rec_value = match utils::json_decode_closer_to_minecraft(receipt_data) {
            Ok(v) => v,
            Err(_) => return,
        };

        if let Some(inner) = rec_value.get("Receipt") {
            self.read_inner_receipt(inner);
        } else {
            self.read_inner_receipt(&rec_value);
        }
    }

    // --- Filesystem-dependent operations ---

    /// Read options.txt to extract `last_minecraft_id` and `last_title_account_id`.
    #[cfg(feature = "native")]
    pub fn read_options_txt(&mut self, options_txt_path: &Path) -> std::io::Result<()> {
        let content = std::fs::read_to_string(options_txt_path)?;
        for line in content.lines() {
            let opt = line.trim();
            if let Some((key, value)) = opt.split_once(':') {
                let key = key.trim();
                let value = value.trim();
                match key {
                    "last_minecraft_id" => self.last_minecraft_id = value.to_uppercase(),
                    "last_title_account_id" => self.last_title_account_id = value.to_uppercase(),
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Pad/repeat `last_title_account_id` to 32 characters.
    fn pad_last_title_account_id(&self) -> String {
        if self.last_title_account_id.is_empty() {
            return String::new();
        }
        let mut result = String::with_capacity(32);
        let bytes = self.last_title_account_id.as_bytes();
        for i in 0..32 {
            result.push(bytes[i % bytes.len()] as char);
        }
        result
    }

    /// Decrypt a version-encrypted entitlement string.
    fn decrypt_entitlement_file(&self, encrypted_ent: &str) -> Option<String> {
        if encrypted_ent.len() < 8 {
            return None;
        }
        let version_str = &encrypted_ent[7..8];
        let version: u32 = version_str.parse().ok()?;

        let version_key = match version {
            2 | _ => b"X(nG*ejm&E8)m+8c;-SkLTjF)*QdN6_Y",
        };

        let derive_text = self.pad_last_title_account_id();
        let ent_key = Self::derive_ent_key(version_key, derive_text.as_bytes());

        let ent_b64 = &encrypted_ent[8..];
        let ent_ciphertext = utils::force_decode_base64(ent_b64)?;

        let key_32 = {
            let mut k = [0u8; 32];
            let len = ent_key.len().min(32);
            k[..len].copy_from_slice(&ent_key[..len]);
            k
        };
        let ent_plaintext =
            crypto::aes256_cfb_decrypt(&key_32, &ent_ciphertext, ent_ciphertext.len());
        String::from_utf8(ent_plaintext).ok()
    }

    /// Read an `.ent` entitlement file and extract content keys.
    #[cfg(feature = "native")]
    pub fn read_entitlement_file(&mut self, ent_path: &Path) -> std::io::Result<()> {
        let json_data = std::fs::read_to_string(ent_path)?;

        let json_data = if json_data.starts_with("Version") {
            match self.decrypt_entitlement_file(&json_data) {
                Some(d) => d,
                None => return Ok(()),
            }
        } else {
            json_data
        };

        if !json_data.trim().ends_with('}') {
            return Ok(());
        }

        let ent_data = match utils::json_decode_closer_to_minecraft(&json_data) {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };

        // Read the Receipt field (base64 or JWT-style base64.token.xxx)
        let receipt_b64 = match ent_data.get("Receipt") {
            Some(v) => match v.as_str() {
                Some(s) => s.to_string(),
                None => return Ok(()),
            },
            None => return Ok(()),
        };

        let receipt_data = if receipt_b64.split('.').count() <= 1 {
            // Plain base64
            match utils::force_decode_base64(&receipt_b64) {
                Some(bytes) => String::from_utf8(bytes).ok(),
                None => None,
            }
        } else {
            // JWT-style: take the second segment (payload)
            let payload = receipt_b64.split('.').nth(1).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid JWT format")
            })?;
            match utils::force_decode_base64(payload) {
                Some(bytes) => String::from_utf8(bytes).ok(),
                None => None,
            }
        };

        match receipt_data {
            Some(data) => self.read_receipt(&data),
            None => return Ok(()),
        }

        // Process Items array if present
        if let Some(items) = ent_data["Items"].as_array() {
            for item in items {
                let b64_data = match item["Receipt"].as_str() {
                    Some(s) => s,
                    None => continue,
                };

                if b64_data.split('.').count() <= 1 {
                    continue;
                }

                let payload = match b64_data.split('.').nth(1) {
                    Some(p) => p,
                    None => continue,
                };

                let recept = match utils::force_decode_base64(payload) {
                    Some(bytes) => match String::from_utf8(bytes) {
                        Ok(s) => s,
                        Err(_) => continue,
                    },
                    None => continue,
                };

                self.read_receipt(&recept);
            }
        }

        Ok(())
    }

    /// Read a keys.db file with `friendlyId=contentKey` lines.
    #[cfg(feature = "native")]
    pub fn read_keys_db(&mut self, key_file: &Path) -> std::io::Result<()> {
        self.key_db_file = key_file.to_string_lossy().to_string();
        let content = std::fs::read_to_string(key_file)?;
        for line in content.lines() {
            if let Some((friendly_id, content_key)) = line.split_once('=') {
                let ck_bytes = content_key.as_bytes().to_vec();
                self.add_key(friendly_id, &ck_bytes, false);
            }
        }
        Ok(())
    }
}

impl Default for Keys {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a string to UTF-16LE bytes (without BOM).
fn to_utf16le(s: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(s.len() * 2);
    for code_unit in s.encode_utf16() {
        bytes.extend_from_slice(&code_unit.to_le_bytes());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key_length() {
        let mut keys = Keys::new();
        let k = keys.generate_key();
        assert_eq!(k.len(), 32);
    }

    #[test]
    fn test_add_and_lookup_key() {
        let mut keys = Keys::new();
        keys.add_key("test-uuid", b"my-content-key", false);
        assert_eq!(keys.lookup_key("test-uuid"), Some(&b"my-content-key"[..]));
        assert!(keys.lookup_key("nonexistent").is_none());
    }

    #[test]
    fn test_derive_content_key() {
        let user_key = b"\x01\x02\x03\x04\x05\x06\x07\x08";
        let content_key = b"\x10\x20\x30\x40\x50\x60\x70\x80";
        let derived = Keys::derive_content_key(user_key, content_key);
        // XOR: 11 22 33 44 55 66 77 88, then take every other: 11 33 55 77
        assert_eq!(derived, vec![0x11, 0x33, 0x55, 0x77]);
    }

    #[test]
    fn test_utf16le() {
        let bytes = to_utf16le("AB");
        assert_eq!(bytes, vec![0x41, 0x00, 0x42, 0x00]);
    }

    #[test]
    fn test_pad_title_account_id() {
        let mut keys = Keys::new();
        keys.last_title_account_id = "ABC".to_string();
        let padded = keys.pad_last_title_account_id();
        assert_eq!(padded.len(), 32);
        assert_eq!(&padded[..3], "ABC");
    }
}

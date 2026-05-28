//! WASM bindings for Minecraft Bedrock marketplace encryption/decryption.
//!
//! # Exports
//!
//! | Function | Input | Output | Description |
//! |---|---|---|---|
//! | `parse_encrypted_header` | `data: &[u8]` | `JsValue { uuid, body }` | Parse 0x100-byte header |
//! | `build_encrypted_header` | `uuid: &str, data: &[u8]` | `Vec<u8>` | Build header + body |
//! | `aes256_cfb8_encrypt` | `key: &[u8], data: &[u8]` | `Vec<u8>` | AES-256-CFB-8 encrypt |
//! | `aes256_cfb8_decrypt` | `key: &[u8], data: &[u8]` | `Vec<u8>` | AES-256-CFB-8 decrypt |
//! | `sha256_digest` | `data: &[u8]` | `Vec<u8>` | SHA-256 hash |

use wasm_bindgen::prelude::*;

use mctools_lib::{crypto, header};

/// Parse the 0x100-byte binary header from encrypted marketplace content.
///
/// Returns `{ uuid: string, body: Uint8Array, version: number }`.
/// Errors are thrown as JS exceptions.
#[wasm_bindgen]
pub fn parse_encrypted_header(data: &[u8]) -> Result<JsValue, JsValue> {
    let parsed = header::parse_encrypted_header(data).map_err(|e| JsValue::from_str(&e))?;

    let result = js_sys::Object::new();
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("version"),
        &JsValue::from_f64(parsed.version as f64),
    )
    .unwrap();
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("uuid"),
        &JsValue::from_str(
            &String::from_utf8(parsed.uuid).unwrap_or_default(),
        ),
    )
    .unwrap();
    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("body"),
        &js_sys::Uint8Array::from(&parsed.body[..]),
    )
    .unwrap();

    Ok(result.into())
}

/// Build the 0x100-byte binary header and prepend it to `data`.
#[wasm_bindgen]
pub fn build_encrypted_header(uuid: &str, data: &[u8]) -> Vec<u8> {
    header::build_encrypted_header_bytes(uuid, data)
}

/// AES-256-CFB-8 encrypt `data` with `key`.
///
/// IV = first 16 bytes of `key`.
/// Output is padded to 16-byte boundary (matches .NET behaviour).
#[wasm_bindgen]
pub fn aes256_cfb8_encrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut k32 = [0u8; 32];
    let len = key.len().min(32);
    k32[..len].copy_from_slice(&key[..len]);
    crypto::aes256_cfb_encrypt(&k32, data)
}

/// AES-256-CFB-8 decrypt `data` with `key`.
///
/// IV = first 16 bytes of `key`.
/// Output length = input length (zero-padding is preserved).
#[wasm_bindgen]
pub fn aes256_cfb8_decrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut k32 = [0u8; 32];
    let len = key.len().min(32);
    k32[..len].copy_from_slice(&key[..len]);
    crypto::aes256_cfb_decrypt(&k32, data, data.len())
}

/// Compute SHA-256 digest of `data`.
#[wasm_bindgen]
pub fn sha256_digest(data: &[u8]) -> Vec<u8> {
    crypto::sha256(data).to_vec()
}

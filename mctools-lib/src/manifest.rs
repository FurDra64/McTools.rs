use std::fs;
use std::path::Path;

use base64::engine::general_purpose;
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ManifestError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Custom(String),
}

pub fn sign_manifest_string(manifest_json: &str, set_path: &str) -> Result<String, ManifestError> {
    let hash = Sha256::digest(manifest_json.as_bytes());
    let b64 = general_purpose::STANDARD.encode(hash);
    let signatures = json!([{"hash": b64, "path": set_path}]);
    Ok(serde_json::to_string(&signatures)?)
}

pub fn sign_manifest(base_path: impl AsRef<Path>) -> Result<(), ManifestError> {
    let base = base_path.as_ref();
    let manifest_path = base.join("manifest.json");
    let content = fs::read(&manifest_path)?;
    let hash = Sha256::digest(&content);
    let b64 = general_purpose::STANDARD.encode(hash);

    let relative = manifest_path
        .strip_prefix(base)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "manifest.json".to_string());

    let signatures = json!([{"hash": b64, "path": relative}]);
    let sig_path = base.join("signatures.json");
    fs::write(sig_path, serde_json::to_string(&signatures)?)?;
    Ok(())
}

pub fn read_type(manifest_file: impl AsRef<Path>) -> Result<String, ManifestError> {
    let manifest_file = manifest_file.as_ref();
    let content = fs::read_to_string(manifest_file)?;
    let manifest: Value = serde_json::from_str(&content)?;

    if let Some(modules) = manifest.get("modules") {
        if let Some(first) = modules.get(0) {
            if let Some(t) = first.get("type") {
                if let Some(s) = t.as_str() {
                    return Ok(s.to_string());
                }
            }
        }
    }

    let parent = manifest_file
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    Ok(parent)
}

pub fn read_product_type(manifest_file: impl AsRef<Path>) -> Result<Option<String>, ManifestError> {
    let content = fs::read_to_string(manifest_file.as_ref())?;
    let manifest: Value = serde_json::from_str(&content)?;

    Ok(manifest
        .get("metadata")
        .and_then(|m| m.get("product_type"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string()))
}

pub fn read_world_pack_list(pack_list_file: impl AsRef<Path>) -> Result<Vec<String>, ManifestError> {
    let content = fs::read_to_string(pack_list_file.as_ref())?;
    let arr: Vec<Value> = serde_json::from_str(&content)?;

    Ok(arr
        .iter()
        .filter_map(|v| v.get("pack_id"))
        .filter_map(|v| v.as_str())
        .map(|s| s.to_string())
        .collect())
}

pub fn read_dependancy_uuids(manifest_file: impl AsRef<Path>) -> Result<Vec<String>, ManifestError> {
    let content = fs::read_to_string(manifest_file.as_ref())?;
    let manifest: Value = serde_json::from_str(&content)?;

    Ok(manifest
        .get("dependencies")
        .and_then(|d| d.as_array())
        .map(|deps| {
            deps.iter()
                .filter_map(|v| v.get("uuid"))
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default())
}

pub fn read_name(manifest_file: impl AsRef<Path>) -> Result<String, ManifestError> {
    let manifest_file = manifest_file.as_ref();
    let manifest_dir = manifest_file
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_default();

    let default_name = manifest_dir
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    let content = fs::read_to_string(manifest_file)?;
    let manifest: Value = serde_json::from_str(&content)?;
    let name = manifest["header"]["name"]
        .as_str()
        .map(|s| s.to_string())
        .unwrap_or_default();

    let lang_file = manifest_dir.join("texts").join("en_US.lang");
    if lang_file.exists() {
        if !name.is_empty() {
            if let Ok(lang_content) = fs::read_to_string(&lang_file) {
                for line in lang_content.lines() {
                    if let Some((key, value)) = line.split_once('=') {
                        let key = key.trim();
                        let value = value.trim();
                        if key == name {
                            return Ok(value.to_string());
                        }
                        if key == "pack.name" {
                            return Ok(value.to_string());
                        }
                        if key.contains('.') && key.rsplit('.').next() == Some(&name) {
                            return Ok(value.to_string());
                        }
                        if key.starts_with("skinpack") {
                            return Ok(value.to_string());
                        }
                        if key.starts_with("persona") {
                            return Ok(value.to_string());
                        }
                        if key.contains(&name) {
                            return Ok(value.to_string());
                        }
                    }
                }
            }
        }
    } else if !name.is_empty() {
        return Ok(name.trim().to_string());
    }

    Ok(default_name.trim().to_string())
}

pub fn read_uuid(manifest_path: impl AsRef<Path>) -> Result<String, ManifestError> {
    let content = fs::read_to_string(manifest_path.as_ref())?;
    let manifest: Value = serde_json::from_str(&content)?;

    manifest["header"]["uuid"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| ManifestError::Custom("Missing header.uuid".to_string()))
}

pub fn change_uuid(manifest_path: impl AsRef<Path>, new_uuid: &str) -> Result<(), ManifestError> {
    let manifest_path = manifest_path.as_ref();
    let content = fs::read_to_string(manifest_path)?;
    let mut manifest: Value = serde_json::from_str(&content)?;

    manifest["header"]["uuid"] = Value::String(new_uuid.to_string());

    fs::write(manifest_path, serde_json::to_string(&manifest)?)?;
    Ok(())
}

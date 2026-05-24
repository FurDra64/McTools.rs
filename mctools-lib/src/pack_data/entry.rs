use std::fs;
use std::path::{Path, PathBuf};

use crate::manifest;

#[derive(Debug, Clone)]
pub struct PEntry {
    file_path: PathBuf,
}

impl PEntry {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            file_path: path.into(),
        }
    }

    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    pub fn manifest_path(&self) -> PathBuf {
        self.file_path.join("manifest.json")
    }

    pub fn world_resource_packs_path(&self) -> PathBuf {
        self.file_path.join("world_resource_packs.json")
    }

    pub fn world_behaviour_packs_path(&self) -> PathBuf {
        self.file_path.join("world_behavior_packs.json")
    }

    pub fn sub_resource_packs(&self) -> PathBuf {
        self.file_path.join("resource_packs")
    }

    pub fn sub_behaviour_packs(&self) -> PathBuf {
        self.file_path.join("behavior_packs")
    }

    pub fn is_encrypted(&self) -> bool {
        if self.product_type() != "minecraftWorlds" {
            return true;
        }
        let db_dir = self.file_path.join("db");
        if db_dir.is_dir() {
            if let Ok(entries) = fs::read_dir(&db_dir) {
                for entry in entries.flatten() {
                    if entry.path().extension().map_or(false, |ext| ext == "ldb") {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn has_dependencies(&self) -> bool {
        !self.depends_uuid().is_empty()
    }

    pub fn depends_uuid(&self) -> Vec<String> {
        let manifest_path = self.manifest_path();
        if manifest_path.exists() {
            return manifest::read_dependancy_uuids(&manifest_path).unwrap_or_default();
        }
        if self.type_name() == "minecraftWorlds" {
            let mut uuids = Vec::new();
            let rp_path = self.world_resource_packs_path();
            if rp_path.exists() {
                uuids.extend(manifest::read_world_pack_list(&rp_path).unwrap_or_default());
            }
            let bp_path = self.world_behaviour_packs_path();
            if bp_path.exists() {
                uuids.extend(manifest::read_world_pack_list(&bp_path).unwrap_or_default());
            }
            return uuids;
        }
        Vec::new()
    }

    pub fn name(&self) -> String {
        let manifest_path = self.manifest_path();
        if manifest_path.exists() {
            return manifest::read_name(&manifest_path).unwrap_or_default();
        }
        let levelname_path = self.file_path.join("levelname.txt");
        if levelname_path.exists() {
            return fs::read_to_string(&levelname_path)
                .unwrap_or_default()
                .trim()
                .to_string();
        }
        "Untitled".to_string()
    }

    pub fn type_name(&self) -> String {
        let manifest_path = self.manifest_path();
        if manifest_path.exists() {
            return manifest::read_type(&manifest_path).unwrap_or_default();
        }
        let levelname_path = self.file_path.join("levelname.txt");
        if levelname_path.exists() {
            return "minecraftWorlds".to_string();
        }
        self.file_path
            .parent()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
    }

    pub fn product_type(&self) -> String {
        let manifest_path = self.manifest_path();
        if manifest_path.exists() {
            if let Ok(Some(ptype)) = manifest::read_product_type(&manifest_path) {
                return ptype;
            }
            let t = manifest::read_type(&manifest_path).unwrap_or_default();
            return match t.as_str() {
                "resources" => "resource_packs",
                "skin_pack" => "skin_packs",
                "world_template" => "world_templates",
                "data" => "behaviour_packs",
                "persona_piece" => "persona",
                _ => &t,
            }
            .to_string();
        }
        let levelname_path = self.file_path.join("levelname.txt");
        if levelname_path.exists() {
            return "minecraftWorlds".to_string();
        }
        if self.has_dependencies() {
            return "addon".to_string();
        }
        self.file_path
            .parent()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
    }

    pub fn uuid(&self) -> String {
        let manifest_path = self.manifest_path();
        if manifest_path.exists() {
            return manifest::read_uuid(&manifest_path).unwrap_or_default();
        }
        "00000000-0000-0000-0000-000000000000".to_string()
    }
}

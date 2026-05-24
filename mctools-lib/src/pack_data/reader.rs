//! Pack discovery scanner. Finds encrypted packs in configured search folders.
//!
//! Ported from McCrypt/PackData/PReader.cs.

use std::collections::HashSet;


use crate::config::Config;
use crate::pack_data::PEntry;

/// Scans Minecraft cache directories for encrypted marketplace packs.
pub struct PReader {
    entries: Vec<PEntry>,
    hidden_uuids: HashSet<String>,
}

impl PReader {
    /// Scan all configured search folders + module combinations for encrypted packs.
    pub fn new(config: &Config) -> Self {
        let mut reader = Self {
            entries: Vec::new(),
            hidden_uuids: HashSet::new(),
        };
        reader.scan(config);
        reader
    }

    fn scan(&mut self, config: &Config) {
        // Search premium cache and other search folders
        for search_folder in config.search_folders() {
            for search_module in config.search_modules() {
                let module_folder = search_folder.join(search_module);
                if !module_folder.is_dir() {
                    continue;
                }

                let dir_entries = match std::fs::read_dir(&module_folder) {
                    Ok(e) => e,
                    Err(_) => continue,
                };

                for entry in dir_entries.flatten() {
                    if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        continue;
                    }

                    let file_path = entry.path();
                    let p_entry = PEntry::new(&file_path);
                    let product_type = p_entry.product_type().to_string();

                    if product_type != "minecraftWorlds" {
                        // Add dependencies of non-world items to hidden_uuids
                        for uuid in p_entry.depends_uuid() {
                            if !self.hidden_uuids.contains(&uuid) {
                                self.hidden_uuids.insert(uuid);
                            }
                        }
                    }

                    if !p_entry.is_encrypted() {
                        continue;
                    }

                    self.entries.push(p_entry);
                }
            }
        }

        // Optionally scan existing worlds
        if config.decrypt_existing_worlds {
            for world_folder in config.worlds_folders() {
                if !world_folder.is_dir() {
                    continue;
                }

                let dir_entries = match std::fs::read_dir(&world_folder) {
                    Ok(e) => e,
                    Err(_) => continue,
                };

                for entry in dir_entries.flatten() {
                    if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        continue;
                    }

                    let file_path = entry.path();
                    let p_entry = PEntry::new(&file_path);

                    for uuid in p_entry.depends_uuid() {
                        if !self.hidden_uuids.contains(&uuid) {
                            self.hidden_uuids.insert(uuid);
                        }
                    }

                    if !p_entry.is_encrypted() {
                        continue;
                    }

                    self.entries.push(p_entry);
                }
            }
        }
    }

    /// Get all discovered pack entries, filtering out hidden UUIDs.
    pub fn pentry_list(&self) -> Vec<&PEntry> {
        self.entries
            .iter()
            .filter(|e| !self.hidden_uuids.contains(&e.uuid()))
            .collect()
    }

    /// Get dependencies of a base entry (recursive lookup across all entries + subpacks).
    pub fn get_dependencies(&self, base_entry: &PEntry) -> Vec<PEntry> {
        let base_uuids: HashSet<String> = base_entry.depends_uuid().into_iter().collect();
        if base_uuids.is_empty() {
            return Vec::new();
        }

        let mut result = Vec::new();

        for pentry in &self.entries {
            if base_uuids.contains(&pentry.uuid()) {
                result.push(pentry.clone());
            }

            // Check sub-packs in world templates
            if pentry.product_type() == "world_templates" {
                let sub_resource = pentry.sub_resource_packs();
                if sub_resource.is_dir() {
                    if let Ok(dir_entries) = std::fs::read_dir(&sub_resource) {
                        for sub_entry in dir_entries.flatten() {
                            if !sub_entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                                continue;
                            }
                            let sub_pentry = PEntry::new(sub_entry.path());
                            if base_uuids.contains(&sub_pentry.uuid()) {
                                result.push(sub_pentry);
                            }
                        }
                    }
                }

                let sub_behaviour = pentry.sub_behaviour_packs();
                if sub_behaviour.is_dir() {
                    if let Ok(dir_entries) = std::fs::read_dir(&sub_behaviour) {
                        for sub_entry in dir_entries.flatten() {
                            if !sub_entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                                continue;
                            }
                            let sub_pentry = PEntry::new(sub_entry.path());
                            if base_uuids.contains(&sub_pentry.uuid()) {
                                result.push(sub_pentry);
                            }
                        }
                    }
                }
            }
        }

        result
    }
}

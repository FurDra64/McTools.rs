use std::env;
use std::fs;
use std::path::{Path, PathBuf, MAIN_SEPARATOR_STR};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    Parse(String),
}

pub type Result<T> = std::result::Result<T, ConfigError>;

pub struct Config {
    pub local_appdata: String,
    pub roaming_appdata: String,
    pub temp: String,
    pub application_folder: PathBuf,
    pub minecraft_folder: PathBuf,
    pub cache_folder: PathBuf,
    pub premium_cache: PathBuf,
    pub server_pack_cache: PathBuf,
    pub realms_premium_cache: PathBuf,
    pub keys_db_path: PathBuf,
    pub out_folder: PathBuf,
    pub users_folder: PathBuf,
    pub crack_packs: bool,
    pub zip_packs: bool,
    pub multi_thread: bool,
    pub decrypt_existing_worlds: bool,

    search_folders: Vec<PathBuf>,
    search_modules: Vec<String>,
    options_txts_pattern: String,
    minecraft_worlds_pattern: String,
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

impl Config {
    pub fn new() -> Self {
        let local_appdata = env::var("LOCALAPPDATA").unwrap_or_else(|_| {
            let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            format!("{}/.local/share", home)
        });
        let roaming_appdata = env::var("APPDATA").unwrap_or_else(|_| {
            let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            format!("{}/.AppData/Roaming", home)
        });
        let temp = env::var("TEMP").unwrap_or_else(|_| "/tmp".to_string());

        let application_folder = env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."));

        let minecraft_folder = PathBuf::from(&roaming_appdata).join("Minecraft Bedrock");
        let cache_folder = PathBuf::from(&temp).join("minecraftpe");
        let keys_db_path = application_folder.join("keys.db");
        let out_folder = application_folder.join("output_packs");

        let mut config = Config {
            local_appdata,
            roaming_appdata,
            temp,
            application_folder,
            minecraft_folder,
            cache_folder,
            premium_cache: PathBuf::new(),
            server_pack_cache: PathBuf::new(),
            realms_premium_cache: PathBuf::new(),
            keys_db_path,
            out_folder,
            users_folder: PathBuf::new(),
            crack_packs: true,
            zip_packs: false,
            multi_thread: true,
            decrypt_existing_worlds: true,
            search_folders: Vec::new(),
            search_modules: Vec::new(),
            options_txts_pattern: String::new(),
            minecraft_worlds_pattern: String::new(),
        };
        config.rebase_local_data();
        config
    }

    pub fn read_config(&mut self, config_file: &Path) -> Result<()> {
        if !config_file.exists() {
            return Err(ConfigError::Parse(format!(
                "Config file not found: {}",
                config_file.display()
            )));
        }

        let content = fs::read_to_string(config_file)?;

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let colon_pos = match trimmed.find(':') {
                Some(p) => p,
                None => continue,
            };

            let key = trimmed[..colon_pos].trim();
            let value = trimmed[colon_pos + 1..].trim();
            if key.is_empty() {
                continue;
            }

            match key {
                "MinecraftFolder" => {
                    self.minecraft_folder = PathBuf::from(self.resolve(value));
                    self.rebase_all();
                }
                "CacheFolder" => {
                    self.cache_folder = PathBuf::from(self.resolve(value));
                    self.rebase_local_data();
                }
                "UsersFolder" => {
                    self.users_folder = PathBuf::from(self.resolve(value));
                    self.rebase_local_data();
                }
                "PremiumCache" => {
                    self.premium_cache = PathBuf::from(self.resolve(value));
                    self.rebase_search_folders();
                }
                "ServerPackCache" => {
                    self.server_pack_cache = PathBuf::from(self.resolve(value));
                    self.rebase_search_folders();
                }
                "RealmsPremiumCache" => {
                    self.realms_premium_cache = PathBuf::from(self.resolve(value));
                    self.rebase_search_folders();
                }
                "OptionsTxt" => {
                    self.options_txts_pattern = self.resolve(value);
                }
                "WorldsFolder" | "MinecraftWorlds" => {
                    self.minecraft_worlds_pattern = self.resolve(value);
                }
                "OutputFolder" => {
                    self.out_folder = PathBuf::from(self.resolve(value));
                }
                "KeysDb" => {
                    self.keys_db_path = PathBuf::from(self.resolve(value));
                }
                "AdditionalSearchDir" => {
                    let resolved = self.resolve(value);
                    if !resolved.is_empty() {
                        self.search_folders.push(PathBuf::from(resolved));
                    }
                }
                "AdditionalModuleDir" => {
                    let resolved = self.resolve(value);
                    if !resolved.is_empty() {
                        self.search_modules.push(resolved);
                    }
                }
                "CrackThePacks" => {
                    self.crack_packs = self.resolve(value).to_lowercase() == "yes";
                }
                "ZipThePacks" => {
                    self.zip_packs = self.resolve(value).to_lowercase() == "yes";
                }
                "MultiThread" => {
                    self.multi_thread = self.resolve(value).to_lowercase() == "yes";
                }
                "DecryptExistingWorlds" => {
                    self.decrypt_existing_worlds = self.resolve(value).to_lowercase() == "yes";
                }
                _ => {}
            }
        }

        Ok(())
    }

    pub fn search_folders(&self) -> &[PathBuf] {
        &self.search_folders
    }

    pub fn search_modules(&self) -> &[String] {
        &self.search_modules
    }

    pub fn options_txts(&self) -> Vec<PathBuf> {
        let mut results = Vec::new();
        let Ok(entries) = fs::read_dir(&self.users_folder) else {
            return results;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let user_dir = path.to_string_lossy().to_string();
            let resolved = self
                .options_txts_pattern
                .replace("$USERDIR", &user_dir)
                .replace('\\', MAIN_SEPARATOR_STR);
            let resolved_path = PathBuf::from(resolved);
            if resolved_path.exists() {
                results.push(resolved_path);
            }
        }
        results
    }

    pub fn worlds_folders(&self) -> Vec<PathBuf> {
        let mut results = Vec::new();
        let Ok(entries) = fs::read_dir(&self.users_folder) else {
            return results;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let user_dir = path.to_string_lossy().to_string();
            let resolved = self
                .minecraft_worlds_pattern
                .replace("$USERDIR", &user_dir)
                .replace('\\', MAIN_SEPARATOR_STR);
            let resolved_path = PathBuf::from(resolved);
            if resolved_path.is_dir() {
                results.push(resolved_path);
            }
        }
        results
    }

    fn resolve(&self, s: &str) -> String {
        let mut s = s.trim().to_string();
        s = s.replace("$LOCALAPPDATA", &self.local_appdata);
        s = s.replace("$APPDATA", &self.roaming_appdata);
        s = s.replace("$TEMP", &self.temp);
        s = s.replace("$MCDIR", &self.minecraft_folder.to_string_lossy());
        s = s.replace("$CACHEDIR", &self.cache_folder.to_string_lossy());
        s = s.replace("$EXECDIR", &self.application_folder.to_string_lossy());
        s = s.replace("$USERSDIR", &self.users_folder.to_string_lossy());
        s = s.replace("$PREMIUMCACHE", &self.premium_cache.to_string_lossy());
        s = s.replace("$SERVERPACKCACHE", &self.server_pack_cache.to_string_lossy());
        s = s.replace("$REALMSPREMIUMCACHE", &self.realms_premium_cache.to_string_lossy());
        s = s.replace("$OUTFOLDER", &self.out_folder.to_string_lossy());
        s = s.replace('\\', MAIN_SEPARATOR_STR);
        s
    }

    fn rebase_all(&mut self) {
        self.minecraft_folder = PathBuf::from(&self.roaming_appdata).join("Minecraft Bedrock");
        self.cache_folder = PathBuf::from(&self.temp).join("minecraftpe");
        self.rebase_local_data();
    }

    pub fn rebase_local_data(&mut self) {
        self.premium_cache = self.minecraft_folder.join("premium_cache");
        self.server_pack_cache = self.cache_folder.join("packcache");
        self.realms_premium_cache = self.cache_folder.join("premiumcache");
        self.users_folder = self.minecraft_folder.join("Users");
        self.minecraft_worlds_pattern = format!(
            "$USERDIR{}games{}com.mojang{}minecraftWorlds",
            MAIN_SEPARATOR_STR,
            MAIN_SEPARATOR_STR,
            MAIN_SEPARATOR_STR,
        );
        self.options_txts_pattern = format!(
            "$USERDIR{}games{}com.mojang{}minecraftpe{}options.txt",
            MAIN_SEPARATOR_STR,
            MAIN_SEPARATOR_STR,
            MAIN_SEPARATOR_STR,
            MAIN_SEPARATOR_STR,
        );
        self.rebase_search_folders();
    }

    fn rebase_search_folders(&mut self) {
        self.search_folders.clear();
        self.search_folders.push(self.application_folder.clone());
        self.search_folders.push(self.premium_cache.clone());
        self.search_folders.push(self.server_pack_cache.clone());
        self.search_folders.push(self.realms_premium_cache.clone());

        self.search_modules.clear();
        self.search_modules.push("resource_packs".to_string());
        self.search_modules.push("skin_packs".to_string());
        self.search_modules.push("world_templates".to_string());
        self.search_modules.push("persona".to_string());
        self.search_modules.push("behavior_packs".to_string());
        self.search_modules.push("resource".to_string());
        self.search_modules.push("minecraftWorlds".to_string());
    }
}

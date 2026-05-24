//! McTools CLI - Decrypt and encrypt Minecraft Bedrock marketplace content.
//!
//! Combines the functionality of the C# McDecryptor and McEncryptor tools.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use clap::{Parser, Subcommand};
use mctools_lib::config::Config;
use mctools_lib::keys::Keys;
use mctools_lib::manifest;
use mctools_lib::marketplace;
use mctools_lib::pack_data::{PEntry, PReader};

/// Escape filename-invalid characters with underscores.
fn escape_filename(filename: &str) -> String {
    filename
        .replace('/', "_")
        .replace('\\', "_")
        .replace(':', "_")
        .replace('?', "_")
        .replace('*', "_")
        .replace('<', "_")
        .replace('>', "_")
        .replace('|', "_")
        .replace('"', "_")
}

/// Recursively copy a directory.
fn copy_directory(source: &Path, target: &Path) -> std::io::Result<()> {
    for entry in walk_dir(source)? {
        let rel = entry.strip_prefix(source).unwrap();
        let dest = target.join(rel);
        if entry.is_dir() {
            std::fs::create_dir_all(&dest)?;
        }
    }
    for entry in walk_dir(source)? {
        if entry.is_file() {
            let rel = entry.strip_prefix(source).unwrap();
            let dest = target.join(rel);
            std::fs::copy(&entry, &dest)?;
        }
    }
    Ok(())
}

/// Walk a directory recursively.
fn walk_dir(path: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut result = Vec::new();
    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            result.push(entry.path());
            if entry.file_type()?.is_dir() {
                result.extend(walk_dir(&entry.path())?);
            }
        }
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Decryption helpers
// ---------------------------------------------------------------------------

/// Decrypt a single pack at the given path.
fn decrypt_pack(
    file_path: &Path,
    entry: &PEntry,
    config: &Config,
    keys: &Keys,
) -> Result<(), Box<dyn std::error::Error>> {
    let level_dat_file = file_path.join("level.dat");
    let skins_json_file = file_path.join("skins.json");
    let old_school_zipe = file_path.join("content.zipe");

    marketplace::decrypt_contents(file_path, &entry.product_type(), keys, false, &Mutex::new(Vec::new()))?;

    save_content_key(file_path, entry, keys);

    if config.crack_packs {
        if old_school_zipe.exists() {
            marketplace::crack_zipe(&old_school_zipe)?;
        }
        if level_dat_file.exists() {
            marketplace::crack_level_dat(&level_dat_file)?;
        }
        if skins_json_file.exists() {
            marketplace::crack_skins_json(&skins_json_file)?;
        }
    }

    Ok(())
}

/// Save content.key file if a key was looked up.
fn save_content_key(pack_path: &Path, entry: &PEntry, keys: &Keys) {
    let manifest_path = entry.manifest_path();
    if !manifest_path.exists() {
        return;
    }

    let uuid = match manifest::read_uuid(&manifest_path) {
        Ok(u) => u,
        Err(_) => return,
    };

    let key = match keys.lookup_key(&uuid) {
        Some(k) => k.to_vec(),
        None => return,
    };

    let pt = entry.product_type();
    if pt == "skin_packs" || pt == "persona" {
        return;
    }

    let key_string = String::from_utf8_lossy(&key);
    let content_key_path = pack_path.join("content.key");
    let _ = std::fs::write(content_key_path, key_string.as_bytes());
}

// ---------------------------------------------------------------------------
// CLI structure
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "mctools", version, about = "Minecraft Bedrock marketplace content decryption/encryption tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to configuration file
    #[arg(short = 'c', long, default_value = "mctools.cfg")]
    config: String,

    /// Path to keys database
    #[arg(short = 'k', long)]
    keys_db: Option<String>,

    /// Output directory
    #[arg(short = 'o', long)]
    output: Option<String>,

    /// Minecraft folder path
    #[arg(long)]
    minecraft_folder: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// List available encrypted packs
    List,
    /// Decrypt packs (interactive or by index)
    Decrypt {
        /// Pack indices (e.g. "1,3,5") or "ALL"
        selections: Option<String>,
    },
    /// Decrypt ALL packs non-interactively
    DecryptAll,
    /// Encrypt a pack directory
    Encrypt {
        /// Path to the pack directory
        pack_path: String,
    },
    /// Extract keys from entitlement (.ent) files
    ExtractKeys,
    /// Export all known keys as JSON
    ExportKeys,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // --- Config ---
    let mut config = Config::new();
    let config_path = Path::new(&cli.config);
    if config_path.exists() {
        config.read_config(config_path)?;
    } else {
        eprintln!("Config file not found: {}, using defaults", cli.config);
    }

    if let Some(k) = &cli.keys_db {
        config.keys_db_path = PathBuf::from(k);
    }
    if let Some(o) = &cli.output {
        config.out_folder = PathBuf::from(o);
    }
    if let Some(m) = &cli.minecraft_folder {
        config.minecraft_folder = PathBuf::from(m);
        config.rebase_local_data();
    }

    // --- Keys ---
    let mut keys = Keys::new();
    keys.key_db_file = config.keys_db_path.to_string_lossy().to_string();

    if config.keys_db_path.exists() {
        eprintln!("Parsing Key Database File...");
        keys.read_keys_db(&config.keys_db_path)?;
    }

    // Read options.txt files and .ent entitlement files
    for options_txt in config.options_txts() {
        eprintln!("Reading options.txt: {}", options_txt.display());
        keys.read_options_txt(&options_txt)?;

        if config.minecraft_folder.is_dir() {
            for entry in std::fs::read_dir(&config.minecraft_folder)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("ent") {
                    eprintln!(
                        "Reading Entitlement File: {}",
                        path.file_name().unwrap_or_default().to_string_lossy()
                    );
                    keys.read_entitlement_file(&path)?;
                }
            }
        }
    }

    match cli.command {
        Commands::List => run_list(&config, &keys),
        Commands::Decrypt { selections } => run_decrypt(&config, &mut keys, selections),
        Commands::DecryptAll => run_decrypt_all(&config, &mut keys),
        Commands::Encrypt { pack_path } => run_encrypt(&pack_path, &mut keys),
        Commands::ExtractKeys => run_extract_keys(&config, &mut keys),
        Commands::ExportKeys => run_export_keys(&keys),
    }
}

// ---------------------------------------------------------------------------
// Subcommand handlers
// ---------------------------------------------------------------------------

fn run_list(config: &Config, _keys: &Keys) -> Result<(), Box<dyn std::error::Error>> {
    let p_reader = PReader::new(config);
    let entries = p_reader.pentry_list();

    println!("Found {} encrypted packs:", entries.len());
    for (i, entry) in entries.iter().enumerate() {
        println!("  {}. ({}) {}", i + 1, entry.product_type(), entry.name());
    }
    Ok(())
}

fn run_decrypt(
    config: &Config,
    keys: &Keys,
    selections: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let p_reader = PReader::new(config);
    let entries = p_reader.pentry_list();

    if entries.is_empty() {
        println!("No encrypted packs found.");
        return Ok(());
    }

    println!("\nSelect what to decrypt: ");
    for (i, entry) in entries.iter().enumerate() {
        println!("  {}. ({}) {}", i + 1, entry.product_type(), entry.name());
    }

    let selections = match selections {
        Some(s) => s,
        None => {
            print!("\nSelect one or multiple (separated by ',') or write \"ALL\": ");
            std::io::stdout().flush()?;
            let mut input = String::new();
            std::io::stdin().lock().read_line(&mut input)?;
            input.trim().to_string()
        }
    };

    let indices = parse_selections(&selections, entries.len());
    process_decrypt_selection(config, keys, &entries, &p_reader, &indices)
}

fn run_decrypt_all(config: &Config, keys: &Keys) -> Result<(), Box<dyn std::error::Error>> {
    let p_reader = PReader::new(config);
    let entries = p_reader.pentry_list();

    if entries.is_empty() {
        println!("No encrypted packs found.");
        return Ok(());
    }

    let indices: Vec<usize> = (0..entries.len()).collect();
    process_decrypt_selection(config, keys, &entries, &p_reader, &indices)
}

fn process_decrypt_selection(
    config: &Config,
    keys: &Keys,
    entries: &[&PEntry],
    p_reader: &PReader,
    indices: &[usize],
) -> Result<(), Box<dyn std::error::Error>> {
    for &idx in indices {
        let entry = entries[idx];
        let out_folder_base = config
            .out_folder
            .join(&entry.product_type())
            .join(escape_filename(&entry.name()));

        let out_folder = unique_path(&out_folder_base);

        println!("\nDecrypting: {}", entry.name());
        std::fs::create_dir_all(&out_folder)?;

        let result = match entry.product_type().as_str() {
            "addon" => decrypt_addon(entry, &out_folder, config, keys, p_reader),
            "minecraftWorlds" => decrypt_world(entry, &out_folder, config, keys, p_reader),
            _ => {
                copy_directory(entry.file_path(), &out_folder)?;
                decrypt_pack(&out_folder, entry, config, keys)
            }
        };

        match result {
            Ok(()) => {
                if config.zip_packs {
                    zip_pack(entry, &out_folder)?;
                }
                println!("  Done: {}", entry.name());
            }
            Err(e) => {
                eprintln!("  Failed to decrypt: {} - {}", entry.name(), e);
                let _ = std::fs::remove_dir_all(&out_folder);
            }
        }
    }

    println!("\nFinished.");
    Ok(())
}

fn decrypt_addon(
    entry: &PEntry,
    out_folder: &Path,
    config: &Config,
    keys: &Keys,
    p_reader: &PReader,
) -> Result<(), Box<dyn std::error::Error>> {
    let sub_dir = out_folder.join(&entry.type_name());
    std::fs::create_dir_all(&sub_dir)?;
    copy_directory(entry.file_path(), &sub_dir)?;
    decrypt_pack(&sub_dir, entry, config, keys)?;

    let deps = p_reader.get_dependencies(entry);
    for dep in deps {
        println!("  Decrypting dependency: {}/{}", dep.type_name(), dep.name());
        let new_dir = out_folder.join(&dep.type_name());
        std::fs::create_dir_all(&new_dir)?;
        copy_directory(dep.file_path(), &new_dir)?;
        decrypt_pack(&new_dir, &dep, config, keys)?;
    }

    Ok(())
}

fn decrypt_world(
    entry: &PEntry,
    out_folder: &Path,
    config: &Config,
    keys: &Keys,
    p_reader: &PReader,
) -> Result<(), Box<dyn std::error::Error>> {
    copy_directory(entry.file_path(), out_folder)?;
    decrypt_pack(out_folder, entry, config, keys)?;

    let deps = p_reader.get_dependencies(entry);
    for dep in deps {
        println!(
            "  Decrypting dependency: {}/{}",
            dep.product_type(),
            dep.name()
        );
        let new_dir = out_folder
            .join(&dep.product_type())
            .join(dep.file_path().file_name().unwrap_or_default());
        std::fs::create_dir_all(new_dir.parent().unwrap())?;
        copy_directory(dep.file_path(), &new_dir)?;
        decrypt_pack(&new_dir, &dep, config, keys)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Zip / packaging
// ---------------------------------------------------------------------------

fn zip_pack(entry: &PEntry, out_folder: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("  Zipping: {}", entry.name());

    let ext = match entry.product_type().as_str() {
        "world_templates" => ".mctemplate",
        "minecraftWorlds" => ".mcworld",
        "addon" => ".mcaddon",
        "persona" => ".mcpersona",
        _ => ".mcpack",
    };

    let fname = PathBuf::from(format!("{}{}", out_folder.display(), ext));

    if fname.exists() {
        std::fs::remove_file(&fname)?;
    }

    let file = std::fs::File::create(&fname)?;
    let mut zip_writer = zip::ZipWriter::new(file);
    let options = zip::write::FileOptions::<()>::default().compression_method(zip::CompressionMethod::Stored);

    add_dir_to_zip(&mut zip_writer, out_folder, out_folder, &options)?;
    zip_writer.finish()?;
    std::fs::remove_dir_all(out_folder)?;

    Ok(())
}

fn add_dir_to_zip(
    zip: &mut zip::ZipWriter<std::fs::File>,
    base: &Path,
    dir: &Path,
    options: &zip::write::FileOptions<()>,
) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = path.strip_prefix(base).unwrap();

        if entry.file_type()?.is_dir() {
            zip.add_directory(name.to_string_lossy(), *options)?;
            add_dir_to_zip(zip, base, &path, options)?;
        } else {
            zip.start_file(name.to_string_lossy(), *options)?;
            let mut f = std::fs::File::open(&path)?;
            std::io::copy(&mut f, zip)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

fn run_encrypt(pack_path: &str, keys: &mut Keys) -> Result<(), Box<dyn std::error::Error>> {
    let pack_path = pack_path.trim().trim_matches('"');
    let pack_dir = Path::new(pack_path);

    if !pack_dir.is_dir() {
        return Err(format!("Directory does not exist: {}", pack_path).into());
    }

    let manifest_path = pack_dir.join("manifest.json");
    let uuid = manifest::read_uuid(&manifest_path)?;

    let ckey = keys.lookup_key(&uuid).map(|k| k.to_vec());
    let mut content_key = "s5s5ejuDru4uchuF2drUFuthaspAbepE".to_string();
    if let Some(ck) = ckey {
        content_key = String::from_utf8_lossy(&ck).to_string();
    }

    println!("uuid: {}", uuid);
    manifest::sign_manifest(pack_dir)?;
    marketplace::encrypt_contents(pack_dir, &uuid, &content_key, keys)?;

    println!("Pack encrypted successfully.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Key extraction / export
// ---------------------------------------------------------------------------

fn run_extract_keys(config: &Config, keys: &mut Keys) -> Result<(), Box<dyn std::error::Error>> {
    if config.minecraft_folder.is_dir() {
        for entry in std::fs::read_dir(&config.minecraft_folder)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("ent") {
                println!("Reading: {}", path.display());
                keys.read_entitlement_file(&path)?;
            }
        }
    }

    for options_txt in config.options_txts() {
        keys.read_options_txt(&options_txt)?;
    }

    println!("Key DB path: {}", config.keys_db_path.display());
    Ok(())
}

fn run_export_keys(keys: &Keys) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", keys.export_keys_json());
    Ok(())
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

fn unique_path(base: &Path) -> PathBuf {
    let mut counter = 1u32;
    let mut out = base.to_path_buf();
    while out.exists() {
        out = PathBuf::from(format!("{}_{}", base.display(), counter));
        counter += 1;
    }
    out
}

fn parse_selections(input: &str, total: usize) -> Vec<usize> {
    let input = input.trim().to_uppercase();
    if input == "ALL" {
        return (0..total).collect();
    }
    input
        .split(',')
        .filter_map(|s| {
            let idx: usize = s.trim().parse().ok()?;
            if idx == 0 || idx > total {
                None
            } else {
                Some(idx - 1)
            }
        })
        .collect()
}

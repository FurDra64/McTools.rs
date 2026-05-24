use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};

use crate::crypto;
use crate::keys::Keys;
use crate::utils;

const DONT_ENCRYPT: &[&str] = &["manifest.json", "contents.json", "texts", "pack_icon.png"];

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ContentsJson {
    version: u32,
    content: Vec<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Cracking
// ---------------------------------------------------------------------------

pub fn crack_level_dat(level_dat_file: &Path) -> std::io::Result<()> {
    let leveldat = std::fs::read(level_dat_file)?;
    let location = utils::find_data(&leveldat, b"prid");
    if location >= 0 {
        let mut file = std::fs::OpenOptions::new().write(true).open(level_dat_file)?;
        file.seek(std::io::SeekFrom::Start(location as u64 + 3))?;
        file.write_all(b"a")?;
    }
    Ok(())
}

pub fn is_level_encrypted(level_path: &Path) -> bool {
    let db_path = level_path.join("db");
    if !db_path.is_dir() {
        return false;
    }
    for entry in std::fs::read_dir(&db_path).unwrap_or_else(|_| std::fs::read_dir("").unwrap()) {
        let entry = match entry { Ok(e) => e, Err(_) => continue };
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("ldb") {
            continue;
        }
        let mut file = match std::fs::File::open(&path) { Ok(f) => f, Err(_) => continue };
        if file.metadata().map(|m| m.len()).unwrap_or(0) <= 0x10 { continue; }
        let mut header = [0u8; 16];
        if file.read_exact(&mut header).is_err() { continue; }
        let magic = u32::from_le_bytes(header[4..8].try_into().unwrap());
        if magic == 0x9bcfb9fc { return true; }
    }
    false
}

pub fn crack_skins_json(skins_json_file: &Path) -> std::io::Result<()> {
    let content = std::fs::read_to_string(skins_json_file)?;
    std::fs::write(skins_json_file, content.replace("\"paid\"", "\"free\""))
}

pub fn crack_zipe(zipe_file: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let parent = zipe_file.parent().unwrap_or(Path::new("."));
    let file = std::fs::File::open(zipe_file)?;
    let mut archive = zip::ZipArchive::new(file)?;
    archive.extract(parent)?;
    std::fs::remove_file(zipe_file)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Entitlement buffer decryption
// ---------------------------------------------------------------------------

pub fn decrypt_entitlement_buffer(ent_ciphertext: &[u8], ent_key: &[u8]) -> Option<Vec<u8>> {
    let mut key_32 = [0u8; 32];
    let len = ent_key.len().min(32);
    key_32[..len].copy_from_slice(&ent_key[..len]);
    Some(crypto::aes256_cfb_decrypt(&key_32, ent_ciphertext, ent_ciphertext.len()))
}

// ---------------------------------------------------------------------------
// Binary header
// ---------------------------------------------------------------------------

fn read_encrypted_header<R: Read>(mut reader: R) -> std::io::Result<(u32, u32, Vec<u8>, Vec<u8>)> {
    let mut hdr = [0u8; 16];
    reader.read_exact(&mut hdr)?;
    let version = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
    let magic = u32::from_le_bytes(hdr[4..8].try_into().unwrap());

    let mut len_byte = [0u8; 1];
    reader.read_exact(&mut len_byte)?;
    let uuid_len = len_byte[0] as usize;
    let mut uuid = vec![0u8; uuid_len];
    if uuid_len > 0 { reader.read_exact(&mut uuid)?; }

    let consumed = 17 + uuid_len;
    let skip = 0x100usize.saturating_sub(consumed);
    if skip > 0 { std::io::copy(&mut reader.by_ref().take(skip as u64), &mut std::io::sink())?; }

    let mut body = Vec::new();
    reader.read_to_end(&mut body)?;
    Ok((version, magic, uuid, body))
}

fn write_encrypted_header<W: Write>(mut w: W, uuid: &str, data: &[u8]) -> std::io::Result<()> {
    w.write_all(&0u32.to_le_bytes())?;
    w.write_all(&0x9bcfb9fcu32.to_le_bytes())?;
    w.write_all(&0u64.to_le_bytes())?;
    let ub = uuid.as_bytes();
    w.write_all(&[ub.len() as u8])?;
    w.write_all(ub)?;
    let pad = 0x100usize.saturating_sub(17 + ub.len());
    let padding = vec![0u8; pad];
    w.write_all(&padding)?;
    w.write_all(data)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

fn should_encrypt(rel_path: &str) -> bool {
    !rel_path.split('/').any(|part| DONT_ENCRYPT.contains(&part))
}

pub fn encrypt_contents(
    base_path: &Path, uuid: &str, content_key: &str, keys: &mut Keys,
) -> Result<String, Box<dyn std::error::Error>> {
    let contents_json_path = base_path.join("contents.json");
    let mut contents = ContentsJson { version: 1, content: Vec::new() };

    for entry in walk_dir(base_path)? {
        let rel = entry.strip_prefix(base_path).unwrap_or(&entry)
            .to_string_lossy().to_string().replace('\\', "/");
        let is_dir = entry.is_dir();
        let rel_path = if is_dir { format!("{}/", rel) } else { rel };

        if should_encrypt(&rel_path) && !is_dir {
            let file_key = keys.generate_key();
            let mut k32 = [0u8; 32];
            let len = file_key.as_bytes().len().min(32);
            k32[..len].copy_from_slice(&file_key.as_bytes()[..len]);
            let enc = crypto::aes256_cfb_encrypt(&k32, &std::fs::read(&entry)?);
            std::fs::write(&entry, enc)?;
            contents.content.push(serde_json::json!({"path": rel_path, "key": file_key}));
        } else {
            contents.content.push(serde_json::json!({"path": rel_path}));
        }
    }

    let json = serde_json::to_string(&contents)?;
    let mut k32 = [0u8; 32];
    let len = content_key.as_bytes().len().min(32);
    k32[..len].copy_from_slice(content_key.as_bytes());
    let enc_json = crypto::aes256_cfb_encrypt(&k32, json.as_bytes());

    let out = std::fs::File::create(&contents_json_path)?;
    write_encrypted_header(out, uuid, &enc_json)?;
    Ok(content_key.to_string())
}

pub fn encrypt_contents_generate_key(
    base_path: &Path, uuid: &str, keys: &mut Keys,
) -> Result<String, Box<dyn std::error::Error>> {
    let ck = keys.generate_key();
    encrypt_contents(base_path, uuid, &ck, keys)
}

// ---------------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------------

pub fn world_or_contents_json_decrypt(
    file_path: &Path, product_type: &str, keys: &Keys,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let file = std::fs::File::open(file_path)?;
    let (_version, _magic, uuid_bytes, encrypted_body) = read_encrypted_header(file)?;
    let uuid_str = String::from_utf8(uuid_bytes)?;

    let key = match keys.lookup_key(&uuid_str) {
        Some(k) => k.to_vec(),
        None if product_type == "skin_packs" || product_type == "persona" =>
            b"s5s5ejuDru4uchuF2drUFuthaspAbepE".to_vec(),
        None => return Err(format!("Key not found for UUID: {}", uuid_str).into()),
    };

    let mut k32 = [0u8; 32];
    let len = key.len().min(32);
    k32[..len].copy_from_slice(&key[..len]);
    Ok(crypto::aes256_cfb_decrypt(&k32, &encrypted_body, encrypted_body.len()))
}

pub fn decrypt_contents(
    contents_path: &Path, product_type: &str, keys: &Keys,
    _multi_thread: bool, _threads: &std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let old_school_zipe = contents_path.join("content.zipe");
    let contents_json_path = contents_path.join("contents.json");

    if old_school_zipe.exists() {
        let dec = world_or_contents_json_decrypt(&old_school_zipe, product_type, keys)?;
        std::fs::write(&old_school_zipe, dec)?;
    } else if contents_json_path.exists() {
        let dec = world_or_contents_json_decrypt(&contents_json_path, product_type, keys)?;
        std::fs::write(&contents_json_path, dec)?;
        decrypt_contents_json_files(&contents_json_path, keys)?;

        let sp = contents_path.join("subpacks");
        if sp.is_dir() {
            for e in std::fs::read_dir(&sp)? {
                let e = e?;
                if e.file_type()?.is_dir() {
                    decrypt_contents(&e.path(), product_type, keys, _multi_thread, _threads)?;
                }
            }
        }
    } else {
        let bp = contents_path.join("behavior_packs");
        if bp.is_dir() {
            for e in std::fs::read_dir(&bp)? {
                let e = e?;
                if e.file_type()?.is_dir() { decrypt_contents(&e.path(), product_type, keys, _multi_thread, _threads)?; }
            }
        }
        let rp = contents_path.join("resource_packs");
        if rp.is_dir() {
            for e in std::fs::read_dir(&rp)? {
                let e = e?;
                if e.file_type()?.is_dir() { decrypt_contents(&e.path(), product_type, keys, _multi_thread, _threads)?; }
            }
        }
        let db = contents_path.join("db");
        if db.is_dir() {
            for path in walk_dir(&db)? {
                if !path.is_file() { continue; }
                if let Ok(dec) = world_or_contents_json_decrypt(&path, product_type, keys) {
                    std::fs::write(&path, dec)?;
                }
            }
        }
    }
    Ok(())
}

fn decrypt_contents_json_files(
    contents_json_path: &Path, _keys: &Keys,
) -> Result<(), Box<dyn std::error::Error>> {
    let base = contents_json_path.parent().unwrap_or(Path::new("."));
    let data: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(contents_json_path)?)?;
    let Some(arr) = data["content"].as_array() else { return Ok(()); };

    for item in arr {
        let Some(rel_path) = item["path"].as_str() else { continue; };
        let Some(dec_key) = item["key"].as_str() else { continue; };
        if Path::new(rel_path).file_name().and_then(|s| s.to_str()) == Some("manifest.json") { continue; }

        let fp = base.join(rel_path);
        if !fp.exists() { continue; }

        let mut k32 = [0u8; 32];
        let len = dec_key.as_bytes().len().min(32);
        k32[..len].copy_from_slice(&dec_key.as_bytes()[..len]);

        let ct = std::fs::read(&fp)?;
        std::fs::write(&fp, crypto::aes256_cfb_decrypt(&k32, &ct, ct.len()))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn walk_dir(path: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut r = Vec::new();
    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            r.push(entry.path());
            if entry.file_type()?.is_dir() { r.extend(walk_dir(&entry.path())?); }
        }
    }
    Ok(r)
}

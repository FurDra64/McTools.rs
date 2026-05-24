//! Utility functions ported from McCrypt.Utils.cs.
//!
//! Provides JSON parsing with lenient truncation, filesystem path inspection,
//! byte-level pattern search, I/O helpers for length-prefixed strings,
//! lenient Base64 decoding, and name trimming.

use base64::Engine as _;
use serde_json::Value;

/// Iterates from the full length of `json` backwards, attempting to parse
/// increasingly shorter prefixes with `serde_json::from_str`.  Returns the
/// first successful parse, or the last error if no prefix succeeds.
pub fn json_decode_closer_to_minecraft(json: &str) -> Result<Value, serde_json::Error> {
    let mut last_err = None;
    for i in (1..=json.len()).rev() {
        let Some(sub) = json.get(..i) else {
            continue;
        };
        if sub.trim().is_empty() {
            continue;
        }
        match serde_json::from_str(sub) {
            Ok(val) => return Ok(val),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| serde_json::from_str::<Value>("").unwrap_err()))
}

/// Returns `true` if `path` is a directory, `false` if it is a regular file,
/// and **panics** if neither exists (matching the C# `FileNotFoundException`).
pub fn is_directory(path: &std::path::Path) -> bool {
    if path.is_dir() {
        true
    } else if path.is_file() {
        false
    } else {
        panic!("Cannot find file: {}", path.display())
    }
}

/// Boyer-Moore-like byte pattern search.
///
/// Scans `data` for the first occurrence of `pattern` and returns its byte
/// offset, or `-1` if the pattern is absent (or longer than `data`).
pub fn find_data(data: &[u8], pattern: &[u8]) -> i64 {
    if pattern.is_empty() || pattern.len() > data.len() {
        return -1;
    }
    let max_start = data.len() - pattern.len();
    for i in 0..=max_start {
        if data[i..i + pattern.len()] == *pattern {
            return i as i64;
        }
    }
    -1
}

/// Reads exactly `len` bytes from `stream` and decodes them as UTF-8.
pub fn read_string(mut stream: impl std::io::Read, len: usize) -> std::io::Result<String> {
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(String::from_utf8(buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?)
}

/// Writes `s` padded with zero bytes to exactly `total_length` bytes.
pub fn write_string(
    mut stream: impl std::io::Write,
    s: &str,
    total_length: u64,
) -> std::io::Result<()> {
    let data = s.as_bytes();
    let data_len = data.len() as u64;
    let padding_len = total_length.saturating_sub(data_len) as usize;

    stream.write_all(data)?;
    if padding_len > 0 {
        let padding = vec![0u8; padding_len];
        stream.write_all(&padding)?;
    }
    Ok(())
}

/// Attempts to Base64-decode `data`, appending `=` padding characters one at a
/// time (up to 20 attempts) until decoding succeeds.
///
/// Returns `None` if all attempts fail.
pub fn force_decode_base64(data: &str) -> Option<Vec<u8>> {
    let engine = base64::engine::general_purpose::STANDARD;
    let mut s = data.to_string();
    for _ in 0..20 {
        if let Ok(decoded) = engine.decode(&s) {
            return Some(decoded);
        }
        s.push('=');
    }
    None
}

/// Strips everything after the first `#` character and trims surrounding
/// whitespace.  If no `#` is present, the whole string is trimmed and
/// returned.
pub fn trim_name(name: &str) -> String {
    match name.find('#') {
        Some(pos) => name[..pos].trim().to_string(),
        None => name.trim().to_string(),
    }
}

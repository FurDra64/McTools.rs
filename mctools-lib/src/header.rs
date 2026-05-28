//! Binary header format for encrypted marketplace content.
//!
//! The 0x100-byte header format:
//!   [0..4)   version    (u32 LE, always 0)
//!   [4..8)   magic      (u32 LE, always 0x9bcfb9fc)
//!   [8..16)  reserved   (u64 LE, always 0)
//!   [16]     uuid_len   (u8)
//!   [17..)   uuid       (uuid_len bytes)
//!   [17+uuid_len..0x100) zero padding
//!   [0x100..)            encrypted body
//!
//! This module is always compiled (even without the `native` feature)
//! so it can be used from WASM targets.

use std::io::{Read, Write};

/// Parsed encrypted header.
#[derive(Debug, Clone)]
pub struct EncryptedHeader {
    pub version: u32,
    pub magic: u32,
    pub uuid: Vec<u8>,
    /// The body after the 0x100-byte header (still encrypted).
    pub body: Vec<u8>,
}

/// Parse the 0x100-byte binary header from encrypted marketplace content.
pub fn parse_encrypted_header(data: &[u8]) -> Result<EncryptedHeader, String> {
    if data.len() < 0x100 {
        return Err(format!(
            "Data too short for header: {} bytes (need >= 0x100)",
            data.len()
        ));
    }

    let version = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let magic = u32::from_le_bytes(data[4..8].try_into().unwrap());

    if magic != 0x9bcfb9fc {
        return Err(format!("Invalid magic number: 0x{:08x}", magic));
    }

    let uuid_len = data[16] as usize;
    let consumed = 17 + uuid_len;
    if consumed > 0x100 {
        return Err(format!("UUID length {} exceeds header capacity", uuid_len));
    }

    let uuid = data[17..consumed].to_vec();
    let body = data[0x100..].to_vec();

    Ok(EncryptedHeader {
        version,
        magic,
        uuid,
        body,
    })
}

/// Read header from any `Read` source.
pub fn read_encrypted_header<R: Read>(mut reader: R) -> std::io::Result<(u32, u32, Vec<u8>, Vec<u8>)> {
    let mut hdr = [0u8; 16];
    reader.read_exact(&mut hdr)?;
    let version = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
    let magic = u32::from_le_bytes(hdr[4..8].try_into().unwrap());

    if magic != 0x9bcfb9fc {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid magic",
        ));
    }

    let mut len_byte = [0u8; 1];
    reader.read_exact(&mut len_byte)?;
    let uuid_len = len_byte[0] as usize;
    let mut uuid = vec![0u8; uuid_len];
    if uuid_len > 0 {
        reader.read_exact(&mut uuid)?;
    }

    let consumed = 17 + uuid_len;
    let skip = 0x100usize.saturating_sub(consumed);
    if skip > 0 {
        std::io::copy(&mut reader.by_ref().take(skip as u64), &mut std::io::sink())?;
    }

    let mut body = Vec::new();
    reader.read_to_end(&mut body)?;
    Ok((version, magic, uuid, body))
}

/// Build the 0x100-byte binary header and prepend it to `body`.
pub fn build_encrypted_header_bytes(uuid: &str, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(0x100 + body.len());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0x9bcfb9fcu32.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    let ub = uuid.as_bytes();
    out.push(ub.len() as u8);
    out.extend_from_slice(ub);
    out.resize(0x100, 0u8);
    out.extend_from_slice(body);
    out
}

/// Write the binary header + body to any `Write` sink.
pub fn write_encrypted_header<W: Write>(mut w: W, uuid: &str, data: &[u8]) -> std::io::Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_header() {
        let uuid = "test-uuid-123";
        let body = b"hello encrypted world";
        let bytes = build_encrypted_header_bytes(uuid, body);
        assert_eq!(bytes.len(), 0x100 + body.len());

        let parsed = parse_encrypted_header(&bytes).unwrap();
        assert_eq!(parsed.version, 0);
        assert_eq!(parsed.magic, 0x9bcfb9fc);
        assert_eq!(parsed.uuid, uuid.as_bytes());
        assert_eq!(parsed.body, body);
    }

    #[test]
    fn test_read_write_header() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let body = b"some encrypted data";
        let mut buf = Vec::new();
        write_encrypted_header(&mut buf, uuid, body).unwrap();

        let (version, magic, parsed_uuid, parsed_body) =
            read_encrypted_header(&buf[..]).unwrap();
        assert_eq!(version, 0);
        assert_eq!(magic, 0x9bcfb9fc);
        assert_eq!(parsed_uuid, uuid.as_bytes());
        assert_eq!(parsed_body, body);
    }

    #[test]
    fn test_parse_too_short() {
        let result = parse_encrypted_header(&[0; 0xff]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_bad_magic() {
        let buf = vec![0u8; 0x200];
        let result = parse_encrypted_header(&buf);
        assert!(result.is_err());
    }
}

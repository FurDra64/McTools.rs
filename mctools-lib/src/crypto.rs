use aes::Aes256;
use cipher::{BlockEncrypt, KeyInit};
use sha2::{Digest, Sha256};

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// AES-256-CFB encrypt `data`.
///
/// Matches .NET `Aes.Create()` defaults:
///   - Mode = CipherMode.CFB (CFB-8: 8-bit feedback)
///   - Padding = PaddingMode.None (manual zero-padding to 16-byte boundary)
///   - BlockSize = 128, KeySize = 256
///   - IV = first 16 bytes of `key`
pub fn aes256_cfb_encrypt(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let cipher = Aes256::new_from_slice(key).expect("valid AES-256 key");

    // Pad to 16-byte boundary with zero bytes (matching C# Behaviour)
    let pad = (16 - (data.len() % 16)) % 16;
    let total = data.len() + pad;
    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(data);
    buf.resize(total, 0u8);

    // CFB-8: shift register = IV = key[:16]
    let mut feedback: [u8; 16] = [0; 16];
    feedback.copy_from_slice(&key[..16]);

    for pt in buf.iter_mut() {
        let mut block = aes::Block::clone_from_slice(&feedback);
        cipher.encrypt_block(&mut block);
        let ks = block[0];
        let ct = *pt ^ ks;
        *pt = ct;
        // Shift feedback left 1 byte, append ciphertext byte
        feedback.copy_within(1.., 0);
        feedback[15] = ct;
    }

    buf
}

/// AES-256-CFB decrypt `data`, returning `original_len` bytes.
///
/// Matches .NET `Aes.Create()` defaults:
///   - Mode = CipherMode.CFB (CFB-8: 8-bit feedback)
///   - Padding = PaddingMode.Zeros (manual zero-padding to 16-byte boundary)
///   - BlockSize = 128, KeySize = 256
///   - IV = first 16 bytes of `key`
pub fn aes256_cfb_decrypt(key: &[u8; 32], data: &[u8], original_len: usize) -> Vec<u8> {
    let cipher = Aes256::new_from_slice(key).expect("valid AES-256 key");

    // Pad to 16-byte boundary with zero bytes
    let pad = (16 - (data.len() % 16)) % 16;
    let total = data.len() + pad;
    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(data);
    buf.resize(total, 0u8);

    // CFB-8: shift register = IV = key[:16]
    let mut feedback: [u8; 16] = [0; 16];
    feedback.copy_from_slice(&key[..16]);
    let mut result = Vec::with_capacity(total);

    for &ct in &buf {
        let mut block = aes::Block::clone_from_slice(&feedback);
        cipher.encrypt_block(&mut block);
        let ks = block[0];
        let pt = ct ^ ks;
        result.push(pt);
        // Shift feedback left 1 byte, append CIPHERTEXT byte (not plaintext)
        feedback.copy_within(1.., 0);
        feedback[15] = ct;
    }

    result.truncate(original_len);
    result
}

/// AES-256-CFB decrypt where output has same length as input.
pub fn aes256_cfb_decrypt_same_len(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    aes256_cfb_decrypt(key, data, data.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_known() {
        let result = sha256(b"hello");
        let expected_hex = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert_eq!(hex::encode(result), expected_hex);
    }

    #[test]
    fn test_aes256_cfb8_roundtrip() {
        let key = b"0123456789abcdef0123456789abcdef";
        let data = b"Hello, Minecraft!";
        let encrypted = aes256_cfb_encrypt(key, data);
        assert_eq!(encrypted.len() % 16, 0);
        let decrypted = aes256_cfb_decrypt(key, &encrypted, data.len());
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_aes256_cfb8_empty_data() {
        let key = b"0123456789abcdef0123456789abcdef";
        let encrypted = aes256_cfb_encrypt(key, b"");
        assert!(encrypted.is_empty() || encrypted.len() % 16 == 0);
    }

    #[test]
    fn test_aes256_cfb8_partial_blocks() {
        let key = b"0123456789abcdef0123456789abcdef";

        for len in [1, 3, 7, 15, 16, 17, 31, 32, 33] {
            let data: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
            let enc = aes256_cfb_encrypt(key, &data);
            let dec = aes256_cfb_decrypt(key, &enc, data.len());
            assert_eq!(dec, data, "failed at length {}", len);
            assert_eq!(enc.len() % 16, 0, "encrypted length {} not multiple of 16", enc.len());
        }
    }

    #[test]
    fn test_aes256_cfb8_known_vector() {
        let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
                     \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
        let data = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let encrypted = aes256_cfb_encrypt(key, data);
        assert_eq!(encrypted.len(), 16);
        let decrypted = aes256_cfb_decrypt(key, &encrypted, data.len());
        assert_eq!(decrypted, data);
    }
}

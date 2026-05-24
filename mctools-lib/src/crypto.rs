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

pub fn aes256_cfb_encrypt(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let cipher = Aes256::new_from_slice(key).expect("valid AES-256 key");
    let pad = (16 - (data.len() % 16)) % 16;
    let total = data.len() + pad;
    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(data);
    buf.resize(total, 0u8);

    let mut feedback = aes::Block::clone_from_slice(&key[..16]);
    for chunk in buf.chunks_mut(16) {
        let mut enc = feedback;
        cipher.encrypt_block(&mut enc);
        for (d, e) in chunk.iter_mut().zip(enc.iter()) {
            *d ^= e;
        }
        feedback = aes::Block::clone_from_slice(chunk);
    }
    buf
}

pub fn aes256_cfb_decrypt(key: &[u8; 32], data: &[u8], original_len: usize) -> Vec<u8> {
    let cipher = Aes256::new_from_slice(key).expect("valid AES-256 key");
    let pad = (16 - (data.len() % 16)) % 16;
    let total = data.len() + pad;
    let mut work = Vec::with_capacity(total);
    work.extend_from_slice(data);
    work.resize(total, 0u8);

    let mut pt = Vec::with_capacity(total);
    let mut fb = aes::Block::clone_from_slice(&key[..16]);
    for chunk in work.chunks(16) {
        let mut enc = fb;
        cipher.encrypt_block(&mut enc);
        for (c, e) in chunk.iter().zip(enc.iter()) {
            pt.push(c ^ e);
        }
        fb = aes::Block::clone_from_slice(chunk);
    }
    pt.truncate(original_len);
    pt
}

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
    fn test_aes256_cfb_roundtrip() {
        let key = b"0123456789abcdef0123456789abcdef";
        let data = b"Hello, Minecraft!";
        let encrypted = aes256_cfb_encrypt(key, data);
        assert_eq!(encrypted.len() % 16, 0);
        let decrypted = aes256_cfb_decrypt(key, &encrypted, data.len());
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_aes256_cfb_empty() {
        let key = b"0123456789abcdef0123456789abcdef";
        let encrypted = aes256_cfb_encrypt(key, b"");
        assert!(encrypted.is_empty() || encrypted.len() % 16 == 0);
    }
}

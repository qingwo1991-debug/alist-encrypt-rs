use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher};
use md5::{Digest, Md5};
use pbkdf2::pbkdf2_hmac;
use rc4::Rc4;
use sha2::Sha256;

#[derive(Debug, Clone, Copy)]
pub enum CryptoMode {
    AesCtr,
    Rc4,
}

pub struct AesCtrCompat {
    key: [u8; 16],
    iv: [u8; 16],
}

type AesCtr128BE = ctr::Ctr128BE<Aes128>;

impl AesCtrCompat {
    pub fn new(password: &str, size_salt: u64) -> Self {
        let outward = passwd_outward(password, b"AES-CTR");
        let mut hasher = Md5::new();
        hasher.update(outward.as_bytes());
        hasher.update(size_salt.to_string().as_bytes());
        let key_bytes = hasher.finalize();

        let mut iv_hasher = Md5::new();
        iv_hasher.update(size_salt.to_string().as_bytes());
        let iv_bytes = iv_hasher.finalize();

        let mut key = [0u8; 16];
        let mut iv = [0u8; 16];
        key.copy_from_slice(&key_bytes[..16]);
        iv.copy_from_slice(&iv_bytes[..16]);
        Self { key, iv }
    }

    pub fn apply(&self, data: &mut [u8], offset: u64) {
        let mut iv = self.iv;
        increment_iv(&mut iv, offset / 16);
        let mut c = AesCtr128BE::new(&self.key.into(), &iv.into());

        let pad = (offset % 16) as usize;
        if pad > 0 {
            let mut skip = vec![0u8; pad];
            c.apply_keystream(&mut skip);
        }
        c.apply_keystream(data);
    }
}

pub struct Rc4Compat {
    key_hex: [u8; 16],
}

impl Rc4Compat {
    pub fn new(password: &str, size_salt: u64) -> Self {
        let outward = passwd_outward(password, b"RC4");
        let mut hasher = Md5::new();
        hasher.update(outward.as_bytes());
        hasher.update(size_salt.to_string().as_bytes());
        let digest = hasher.finalize();
        let mut key_hex = [0u8; 16];
        key_hex.copy_from_slice(&digest[..16]);
        Self { key_hex }
    }

    pub fn apply(&self, data: &mut [u8], offset: u64) {
        use rc4::cipher::KeyInit;
        let mut cipher = Rc4::<rc4::consts::U16>::new_from_slice(&self.key_hex).unwrap();

        if offset > 0 {
            let mut skip = vec![0u8; offset as usize];
            cipher.apply_keystream(&mut skip);
        }
        cipher.apply_keystream(data);
    }
}

pub fn apply_crypto(
    mode: CryptoMode,
    password: &str,
    size_salt: u64,
    data: &mut [u8],
    offset: u64,
) {
    match mode {
        CryptoMode::AesCtr => AesCtrCompat::new(password, size_salt).apply(data, offset),
        CryptoMode::Rc4 => Rc4Compat::new(password, size_salt).apply(data, offset),
    }
}

pub fn passwd_outward(password: &str, algo: &[u8]) -> String {
    if password.len() == 32 && password.chars().all(|c| c.is_ascii_hexdigit()) {
        return password.to_string();
    }
    let mut out = [0u8; 16];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), algo, 1000, &mut out);
    hex::encode(out)
}

fn increment_iv(iv: &mut [u8; 16], blocks: u64) {
    let mut n = blocks;
    for idx in (0..16).rev() {
        let add = (n & 0xff) as u8;
        let (new, carry) = iv[idx].overflowing_add(add);
        iv[idx] = new;
        n >>= 8;
        if !carry && n == 0 {
            break;
        }
        if carry {
            let mut j = idx;
            while j > 0 {
                j -= 1;
                let (v, c2) = iv[j].overflowing_add(1);
                iv[j] = v;
                if !c2 {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{apply_crypto, CryptoMode};

    #[test]
    fn aes_ctr_roundtrip_with_offset() {
        let password = "abc123456";
        let size_salt = 1024_u64;
        let plain = b"hello-\xE4\xB8\xAD\xE6\x96\x87-+-()--range";
        let mut enc = plain.to_vec();
        apply_crypto(CryptoMode::AesCtr, password, size_salt, &mut enc, 0);
        assert_ne!(enc, plain);

        let mut dec = enc.clone();
        apply_crypto(CryptoMode::AesCtr, password, size_salt, &mut dec, 0);
        assert_eq!(dec, plain);

        let mut part = plain[7..].to_vec();
        apply_crypto(CryptoMode::AesCtr, password, size_salt, &mut part, 7);
        let mut part_dec = part.clone();
        apply_crypto(CryptoMode::AesCtr, password, size_salt, &mut part_dec, 7);
        assert_eq!(part_dec, plain[7..]);
    }

    #[test]
    fn rc4_roundtrip() {
        let password = "abc123456";
        let size_salt = 99_u64;
        let plain = b"rc4-data";
        let mut enc = plain.to_vec();
        apply_crypto(CryptoMode::Rc4, password, size_salt, &mut enc, 0);
        assert_ne!(enc, plain);

        let mut dec = enc;
        apply_crypto(CryptoMode::Rc4, password, size_salt, &mut dec, 0);
        assert_eq!(dec, plain);
    }
}

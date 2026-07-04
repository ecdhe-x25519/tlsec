use libc::{
    tls12_crypto_info_aes_gcm_128, tls12_crypto_info_aes_gcm_256,
    tls12_crypto_info_chacha20_poly1305, tls_crypto_info
};

use std::mem;

use crate::encryption::cipher_suite::AnyCipher;

#[derive(Debug)]
pub enum TlsCryptoInfo {
    Aes128Info(tls12_crypto_info_aes_gcm_128),
    Aes256Info(tls12_crypto_info_aes_gcm_256),
    ChaCha20Info(tls12_crypto_info_chacha20_poly1305),
}

impl TlsCryptoInfo {
    pub fn new(cipher: &AnyCipher) -> Self {
        match cipher {
            AnyCipher::Aes128Gcm(c) => TlsCryptoInfo::Aes128Info(tls12_crypto_info_aes_gcm_128 {
                info: tls_crypto_info { version: c.version, cipher_type: c.typ },
                iv: c.iv,
                key: c.key,
                salt: c.salt,
                rec_seq: c.rec_seq.to_le_bytes(),
            }),
            AnyCipher::Aes256Gcm(c) => TlsCryptoInfo::Aes256Info(tls12_crypto_info_aes_gcm_256 {
                info: tls_crypto_info { version: c.version, cipher_type: c.typ },
                iv: c.iv,
                key: c.key,
                salt: c.salt,
                rec_seq: c.rec_seq.to_le_bytes(),
            }),
            AnyCipher::ChaCha20Poly1305(c) => TlsCryptoInfo::ChaCha20Info(tls12_crypto_info_chacha20_poly1305 {
                info: tls_crypto_info { version: c.version, cipher_type: c.typ },
                iv: c.iv,
                key: c.key,
                salt: c.salt,
                rec_seq: c.rec_seq.to_le_bytes(),
            }),
        }
    }

    pub(crate) fn as_ptr(&self) -> *const tls_crypto_info {
        match self {
            TlsCryptoInfo::Aes128Info(info) => &info.info as *const _,
            TlsCryptoInfo::Aes256Info(info) => &info.info as *const _,
            TlsCryptoInfo::ChaCha20Info(info) => &info.info as *const _,
        }
    }

    pub(crate) fn size(&self) -> usize {
        match self {
            TlsCryptoInfo::Aes128Info(_) => mem::size_of::<tls12_crypto_info_aes_gcm_128>(),
            TlsCryptoInfo::Aes256Info(_) => mem::size_of::<tls12_crypto_info_aes_gcm_256>(),
            TlsCryptoInfo::ChaCha20Info(_) => mem::size_of::<tls12_crypto_info_chacha20_poly1305>(),
        }
    }
}
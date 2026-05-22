use ring::hkdf::{self, HKDF_SHA256, HKDF_SHA384};
use ring::digest::{self, SHA256, SHA384};

use crate::encryption::cipher_suite::{AnyCipher, TlsCipher};

use crate::error::Error;
use crate::messages::handshake::CipherSuite;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedCipherSuite {
    ChaCha20,
    Aes128,
    Aes256,
}

impl SupportedCipherSuite {
    pub fn key_len(&self) -> usize {
        match self {
            Self::ChaCha20 => 32,
            Self::Aes128 => 16,
            Self::Aes256 => 32,
        }
    }

    pub fn iv_len(&self) -> usize { 12 }

    pub fn hash_algorithm(&self) -> &'static digest::Algorithm {
        match self {
            Self::ChaCha20 => &SHA256,
            Self::Aes128 => &SHA256,
            Self::Aes256 => &SHA384,
        }
    }

    pub fn hash_len(&self) -> usize {
        match self {
            Self::ChaCha20 => 32,
            Self::Aes128 => 32,
            Self::Aes256 => 48,
        }
    }

    pub fn hkdf_algorithm(&self) -> hkdf::Algorithm {
        match self {
            Self::ChaCha20 => HKDF_SHA256,
            Self::Aes128 => HKDF_SHA256,
            Self::Aes256 => HKDF_SHA384,
        }
    }

    pub fn create_cipher(&self, key: Vec<u8>, iv: Vec<u8>) -> Result<AnyCipher, Error> {
        match self {
            Self::ChaCha20 => {
                let key_arr: [u8; 32] = key.try_into().map_err(|_| Error::Crypto("invalid key length".to_string()))?;
                let iv_arr: [u8; 12] = iv.try_into().map_err(|_| Error::Crypto("invalid iv length".to_string()))?;
                Ok(AnyCipher::ChaCha20(TlsCipher::new(key_arr, iv_arr)))
            }
            Self::Aes128 => {
                let key_arr: [u8; 16] = key.try_into().map_err(|_| Error::Crypto("invalid key length".to_string()))?;
                let iv_arr: [u8; 12] = iv.try_into().map_err(|_| Error::Crypto("invalid iv length".to_string()))?;
                Ok(AnyCipher::Aes128(TlsCipher::new(key_arr, iv_arr)))
            }
            Self::Aes256 => {
                let key_arr: [u8; 32] = key.try_into().map_err(|_| Error::Crypto("invalid key length".to_string()))?;
                let iv_arr: [u8; 12] = iv.try_into().map_err(|_| Error::Crypto("invalid iv length".to_string()))?;
                Ok(AnyCipher::Aes256(TlsCipher::new(key_arr, iv_arr)))
            }
        }
    }

    pub fn compare(&self, cipher: &CipherSuite) -> Option<SupportedCipherSuite> {
        match cipher {
            CipherSuite::TlsChacha20Poly1305Sha256 => Some(Self::ChaCha20),
            CipherSuite::TlsAes128GcmSha256 => Some(Self::Aes128),
            CipherSuite::TlsAes256GcmSha384 => Some(Self::Aes256),
            _ => None,
        }
    }
}
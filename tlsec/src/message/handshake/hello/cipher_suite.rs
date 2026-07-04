use crate::message::handshake::grease::GreasePayloadU16;

use crate::encryption::cipher_suite::*;

use crate::error::*;

use ring::hkdf::{self, HKDF_SHA256, HKDF_SHA384};
use ring::digest::{self, SHA256, SHA384};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    TlsAes128GcmSha256,
    TlsAes256GcmSha384,
    TlsChacha20Poly1305Sha256,
    TlsAes128CcmSha256,
    TlsAes128Ccm8Sha256,
    Grease(GreasePayloadU16),
    Unknown(u16),
}

impl CipherSuite {
    pub fn to_supported(&self) -> Option<SupportedCipherSuite> {
        match self {
            CipherSuite::TlsChacha20Poly1305Sha256 => Some(SupportedCipherSuite::ChaCha20),
            CipherSuite::TlsAes128GcmSha256 => Some(SupportedCipherSuite::Aes128),
            CipherSuite::TlsAes256GcmSha384 => Some(SupportedCipherSuite::Aes256),
            _ => None,
        }
    }
}

impl Into<u16> for CipherSuite {
    fn into(self) -> u16 {
        match self {
            Self::TlsAes128GcmSha256 => 0x1301,
            Self::TlsAes256GcmSha384 => 0x1302,
            Self::TlsChacha20Poly1305Sha256 => 0x1303,
            Self::TlsAes128CcmSha256 => 0x1304,
            Self::TlsAes128Ccm8Sha256 => 0x1305,
            Self::Grease(g) => g.grease,
            Self::Unknown(g) => g,
        }
    }
}

impl TryFrom<u16> for CipherSuite {
    type Error = TlsError;
    
    fn try_from(value: u16) -> TlsResult<Self> {
        match value {
            0x1301 => Ok(Self::TlsAes128GcmSha256),
            0x1302 => Ok(Self::TlsAes256GcmSha384),
            0x1303 => Ok(Self::TlsChacha20Poly1305Sha256),
            0x1304 => Ok(Self::TlsAes128CcmSha256),
            0x1305 => Ok(Self::TlsAes128Ccm8Sha256),
            _ => match GreasePayloadU16::is_grease(value) {
                Ok(g) => Ok(Self::Grease(g)),
                Err(_) => Ok(Self::Unknown(value)),
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedCipherSuite {
    ChaCha20,
    Aes128,
    Aes256,
}

impl SupportedCipherSuite {
    pub fn to_unsupported(&self) -> CipherSuite {
        match self {
            SupportedCipherSuite::Aes128 => CipherSuite::TlsAes128GcmSha256,
            SupportedCipherSuite::Aes256 => CipherSuite::TlsAes256GcmSha384,
            SupportedCipherSuite::ChaCha20 => CipherSuite::TlsChacha20Poly1305Sha256,
        }
    }

    pub fn hkdf_based_key_len(&self) -> usize {
        match self {
            Self::ChaCha20 => 32,
            Self::Aes128 => 32,
            Self::Aes256 => 48,
        }
    }

    pub fn true_key_len(&self) -> usize {
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

    pub fn create_cipher(&self, key: Vec<u8>, iv: Vec<u8>) -> TlsResult<AnyCipher> {
        match self {
            Self::ChaCha20 => {
                let key_arr: [u8; 32] = key.try_into().map_err(|_| TlsError::Crypto("invalid key length".to_string()))?;
                let iv_arr: [u8; 12] = iv.try_into().map_err(|_| TlsError::Crypto("invalid iv length".to_string()))?;
                Ok(AnyCipher::ChaCha20Poly1305(ChaCha20::new(key_arr, iv_arr)))
            }
            Self::Aes128 => {
                let key_arr: [u8; 16] = key.try_into().map_err(|_| TlsError::Crypto("invalid key length".to_string()))?;
                let iv_arr: [u8; 12] = iv.try_into().map_err(|_| TlsError::Crypto("invalid iv length".to_string()))?;
                Ok(AnyCipher::Aes128Gcm(Aes128::new(key_arr, iv_arr)))
            }
            Self::Aes256 => {
                let key_arr: [u8; 32] = key.try_into().map_err(|_| TlsError::Crypto("invalid key length".to_string()))?;
                let iv_arr: [u8; 12] = iv.try_into().map_err(|_| TlsError::Crypto("invalid iv length".to_string()))?;
                Ok(AnyCipher::Aes256Gcm(Aes256::new(key_arr, iv_arr)))
            }
        }
    }
}

#[cfg(test)]
mod test_cipher_suite_parse {
    
}
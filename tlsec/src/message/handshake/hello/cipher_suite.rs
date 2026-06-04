use crate::message::handshake::grease::is_grease_u16;

use crate::encryption::cipher_suite::{AnyCipher, TlsCipher};

use crate::error::Error;

use ring::hkdf::{self, HKDF_SHA256, HKDF_SHA384};
use ring::digest::{self, SHA256, SHA384};

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    TlsAes128GcmSha256 = 0x1301,
    TlsAes256GcmSha384 = 0x1302,
    TlsChacha20Poly1305Sha256 = 0x1303,
    TlsAes128CcmSha256 = 0x1304,
    TlsAes128Ccm8Sha256 = 0x1305,
    Grease,
}

impl TryFrom<u16> for CipherSuite {
    type Error = Error;
    
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x1301 => Ok(Self::TlsAes128GcmSha256),
            0x1302 => Ok(Self::TlsAes256GcmSha384),
            0x1303 => Ok(Self::TlsChacha20Poly1305Sha256),
            0x1304 => Ok(Self::TlsAes128CcmSha256),
            0x1305 => Ok(Self::TlsAes128Ccm8Sha256),
            _ => if is_grease_u16(value) {
                Ok(CipherSuite::Grease)
            } else {
                Err(Error::Unknown("cipher suite"))
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

#[cfg(test)]
mod test_cipher_suite_parse {
    
}
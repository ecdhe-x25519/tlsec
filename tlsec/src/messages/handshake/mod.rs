pub mod handshake;
pub mod extensions;

use crate::encryption::Random;

use crate::error::Error;

use bytes::{Buf, BytesMut, BufMut};

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
                Err(Error::UnsupportedCipherSuite)
            }
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionMethod {
    Null = 0,
    DEFLATE = 1,
    LZS = 64,
}

impl TryFrom<u8> for CompressionMethod {
    type Error = Error;
    
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Null),
            1 => Ok(Self::DEFLATE),
            64 => Ok(Self::LZS),
            _ => Err(Error::UnsupportedCompressionMethod)
        }
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureScheme {
    RsaPssSha256 = 0x0804,
    RsaPssSha384 = 0x0805,
    RsaPssSha512 = 0x0806,
    EcdsaSecp256r1Sha256 = 0x0403,
    EcdsaSecp384r1Sha384 = 0x0503,
    EcdsaSecp521r1Sha512 = 0x0603,
    Ed25519 = 0x0807,
    Ed448 = 0x0808,
    Grease,
}

impl TryFrom<u16> for SignatureScheme {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0804 => Ok(Self::RsaPssSha256),
            0x0805 => Ok(Self::RsaPssSha384),
            0x0806 => Ok(Self::RsaPssSha512),
            0x0403 => Ok(Self::EcdsaSecp256r1Sha256),
            0x0503 => Ok(Self::EcdsaSecp384r1Sha384),
            0x0603 => Ok(Self::EcdsaSecp521r1Sha512),
            0x0807 => Ok(Self::Ed25519),
            0x0808 => Ok(Self::Ed448),
            _ => if is_grease_u16(value) {
                Ok(Self::Grease)
            } else {
                Err(Error::UnsupportedSignatureScheme)
            }
        }
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum NamedGroup {
    X25519 = 0x1D,
    Secp256r1 = 0x17,
    Secp384r1 = 0x18,
    X25519MLKEM768 = 0x11EC,
    Grease,
}

impl TryFrom<u16> for NamedGroup {
    type Error = Error;
    
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x1D => Ok(Self::X25519),
            0x17 => Ok(Self::Secp256r1),
            0x18 => Ok(Self::Secp384r1),
            0x11EC => Ok(Self::X25519MLKEM768),
            _ => if is_grease_u16(value) {
                Ok(Self::Grease)
            } else {
                Err(Error::UnsupportedNamedGroup)
            }
        }
    }
}

pub const GREASE_U8_VALUES: [u8; 16] = [
    0x0A, 0x1A, 0x2A, 0x3A, 0x4A, 0x5A, 0x6A, 0x7A,
    0x8A, 0x9A, 0xAA, 0xBA, 0xCA, 0xDA, 0xEA, 0xFA,
];

pub const GREASE_U16_VALUES: [u16; 16] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

pub fn grease_u8(rng: &Random) -> Result<u8, Error> {
    let mut idx: [u8; 1] = [0u8; 1];
    rng.secure_random(&mut idx).map_err(|e| Error::Crypto(format!("RNG failed: {e}")))?;
    Ok(GREASE_U8_VALUES[(idx[0] as usize) % 8])
}

pub fn grease_u16(rng: &Random) -> Result<u16, Error> {
    let mut idx: [u8; 1] = [0u8; 1];
    rng.secure_random(&mut idx).map_err(|e| Error::Crypto(format!("RNG failed: {e}")))?;
    Ok(GREASE_U16_VALUES[(idx[0] as usize) % 16])
}

pub fn is_grease_u8(value: u8) -> bool {
    (value & 0x0F) == 0x0A
}

pub fn is_grease_u16(value: u16) -> bool {
    let b1: u8 = (value >> 8) as u8;
    let b2: u8 = (value & 0xFF) as u8;
    b1 == b2 && (b1 & 0x0F) == 0x0A
}
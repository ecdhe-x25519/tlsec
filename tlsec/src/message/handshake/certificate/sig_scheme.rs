use crate::message::handshake::grease::is_grease_u16;
use crate::message::serialize::Serialize;

use crate::error::*;

use bytes::*;

use webpki::{ECDSA_P256_SHA256, ECDSA_P384_SHA384, ED25519, SignatureAlgorithm};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureAlgorithmsPayload {
    pub schemes: Vec<SignatureScheme>, // length = u16
}

impl Serialize for SignatureAlgorithmsPayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16((self.schemes.len() * 2) as u16);
        for scheme in &self.schemes {
            buf.put_u16(*scheme as u16);
        }
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let list_length: usize = buf.get_u16() as usize;

        if buf.remaining() < list_length {
            return Err(Error::Incomplete(list_length - buf.remaining()));
        }

        let mut schemes: Vec<SignatureScheme> = Vec::new();
        for _ in 0..list_length / 2 {
            schemes.push(SignatureScheme::try_from(buf.get_u16())?);
        }

        Ok(Self { schemes })
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
                Err(Error::Unknown("signature scheme"))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedScheme {
    Ed25519,
    EcdsaSecp256r1Sha256,
    EcdsaSecp384r1Sha384,
}

impl SupportedScheme {
    pub fn compare(&self, scheme: &SignatureScheme) -> Option<SupportedScheme> {
        match scheme {
            SignatureScheme::Ed25519 => Some(Self::Ed25519),
            SignatureScheme::EcdsaSecp256r1Sha256 => Some(Self::EcdsaSecp256r1Sha256),
            SignatureScheme::EcdsaSecp384r1Sha384 => Some(Self::EcdsaSecp384r1Sha384),
            _ => None,
        }
    }

    pub fn to_algo(&self) -> &SignatureAlgorithm {
        match self {
            Self::Ed25519 => &ED25519,
            Self::EcdsaSecp256r1Sha256 => &ECDSA_P256_SHA256,
            Self::EcdsaSecp384r1Sha384 => &ECDSA_P384_SHA384,
        }
    }
}

#[cfg(test)]
mod test_sig_schemes_parse {
    
}
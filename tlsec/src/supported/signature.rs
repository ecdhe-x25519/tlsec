use webpki::{ECDSA_P256_SHA256, ECDSA_P384_SHA384, ED25519, SignatureAlgorithm};

use crate::messages::handshake::SignatureScheme;

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
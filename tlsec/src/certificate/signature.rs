use webpki::{ECDSA_P256_SHA256, ECDSA_P384_SHA384, ED25519, SignatureAlgorithm};

pub enum SupportedSchemes {
    Ed25519,
    EcdsaSecp256r1Sha256,
    EcdsaSecp384r1Sha384,
}

impl SupportedSchemes {
    pub fn to_algo(&self) -> &SignatureAlgorithm {
        match self {
            Self::Ed25519 => &ED25519,
            Self::EcdsaSecp256r1Sha256 => &ECDSA_P256_SHA256,
            Self::EcdsaSecp384r1Sha384 => &ECDSA_P384_SHA384,
        }
    }
}
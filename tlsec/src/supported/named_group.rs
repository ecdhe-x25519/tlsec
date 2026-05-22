use crate::messages::handshake::NamedGroup;

use ring::agreement::{self, ECDH_P256, ECDH_P384, X25519};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedNamedGroup {
    X25519,
    Secp256R1,
    Secp384R1,
}

impl SupportedNamedGroup {
    pub fn compare(&self, named_group: &NamedGroup) -> Option<SupportedNamedGroup> {
        match named_group {
            NamedGroup::X25519 => Some(Self::X25519),
            NamedGroup::Secp256r1 => Some(Self::Secp256R1),
            NamedGroup::Secp384r1 => Some(Self::Secp384R1),
            _ => None,
        }
    }

    pub fn to_curve(self) -> &'static agreement::Algorithm {
        match self {
            Self::X25519 => &X25519,
            Self::Secp256R1 => &ECDH_P256,
            Self::Secp384R1 => &ECDH_P384,
        }
    }
}
use crate::message::serialize::Serialize;
use crate::message::handshake::grease::is_grease_u16;

use crate::error::TlsError;

use ring::agreement::{self, ECDH_P256, ECDH_P384, X25519};

use bytes::*;

#[derive(Debug, PartialEq, Eq)]
pub struct KeyShareEntry {
    pub group: NamedGroup,
    pub key_exchange: Bytes, // length = u16
}

impl Serialize for KeyShareEntry {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.group as u16);
        buf.put_u16(self.key_exchange.len() as u16);
        buf.put_slice(&self.key_exchange);
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, TlsError> {
        if buf.remaining() < 2 {
            return Err(TlsError::Incomplete(2 - buf.remaining()));
        }

        let group: NamedGroup = NamedGroup::try_from(buf.get_u16())?;
        
        if buf.remaining() < 2 {
            return Err(TlsError::Incomplete(2 - buf.remaining()));
        }

        let key_len: usize = buf.get_u16() as usize;
        if buf.remaining() < key_len {
            return Err(TlsError::Incomplete(key_len - buf.remaining()));
        }

        let key_exchange: Bytes = buf.split_to(key_len).freeze();
        
        Ok(Self { group, key_exchange })
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedGroup {
    X25519 = 0x1D,
    Secp256r1 = 0x17,
    Secp384r1 = 0x18,
    X25519MLKEM768 = 0x11EC,
    Grease,
}

impl TryFrom<u16> for NamedGroup {
    type Error = TlsError;
    
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x1D => Ok(Self::X25519),
            0x17 => Ok(Self::Secp256r1),
            0x18 => Ok(Self::Secp384r1),
            0x11EC => Ok(Self::X25519MLKEM768),
            _ => if is_grease_u16(value) {
                Ok(Self::Grease)
            } else {
                Err(TlsError::Unknown("named group"))
            }
        }
    }
}

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

#[cfg(test)]
mod test_key_share_parse {
    
}
use crate::{error::*, message::{handshake::grease::GreasePayloadU16, serialize::Serialize}};

use ring::agreement::{self, ECDH_P256, ECDH_P384, X25519};

use bytes::*;
use brevno::*;

#[derive(Debug, PartialEq, Eq)]
pub struct KeySharePayload {
    pub key_shares: Vec<KeyShareEntry>, // length = u16
}

impl Serialize for KeySharePayload {
    fn encode(&self, buf: &mut BytesMut) {
        let mut inner: BytesMut = BytesMut::new();
        for share in &self.key_shares {
            share.encode(&mut inner);
        }
        buf.put_u16(inner.len() as u16);
        buf.put_slice(&inner);
    }

    fn decode(buf: &mut BytesMut) -> TlsResult<Self> {
        if buf.remaining() < 2 {
            error!(format!("Incomplete data: need {} more bytes", (2 - buf.remaining())));
            return Err(TlsError::Incomplete(2 - buf.remaining()));
        }

        let list_length: usize = buf.get_u16() as usize;

        if buf.remaining() < list_length {
            error!(format!("Incomplete data: need {} more bytes", (list_length - buf.remaining())));
            return Err(TlsError::Incomplete(list_length - buf.remaining()));
        }

        let mut data: BytesMut = buf.split_to(list_length);

        let mut key_shares: Vec<KeyShareEntry> = Vec::new();
        while data.has_remaining() {
            key_shares.push(KeyShareEntry::decode(&mut data)?);
        }

        Ok(Self { key_shares })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct KeyShareEntry {
    pub group: NamedGroup,
    pub key_exchange: Bytes, // length = u16
}

impl Serialize for KeyShareEntry {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.group.into());
        buf.put_u16(self.key_exchange.len() as u16);
        buf.put_slice(&self.key_exchange);
    }

    fn decode(buf: &mut BytesMut) -> TlsResult<Self> {
        if buf.remaining() < 4 {
            error!(format!("Incomplete data: need {} more bytes", (4 - buf.remaining())));
            return Err(TlsError::Incomplete(4 - buf.remaining()));
        }

        let group: NamedGroup = NamedGroup::try_from(buf.get_u16())?;

        let key_len: usize = buf.get_u16() as usize;

        if buf.remaining() < key_len {
            error!(format!("Incomplete data: need {} more bytes", (key_len - buf.remaining())));
            return Err(TlsError::Incomplete(key_len - buf.remaining()));
        }

        let key_exchange: Bytes = buf.split_to(key_len).freeze();
        
        Ok(Self { group, key_exchange })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedGroup {
    X25519,
    Secp256r1,
    Secp384r1,
    X25519MLKEM768,
    Grease(GreasePayloadU16),
    Unknown(u16),
}

impl NamedGroup {
    pub fn to_supported(&self) -> Option<SupportedNamedGroup> {
        match self {
            NamedGroup::X25519 => Some(SupportedNamedGroup::X25519),
            NamedGroup::Secp256r1 => Some(SupportedNamedGroup::Secp256R1),
            NamedGroup::Secp384r1 => Some(SupportedNamedGroup::Secp384R1),
            _ => None,
        }
    }
}

impl Into<u16> for NamedGroup {
    fn into(self) -> u16 {
        match self {
            Self::X25519 => 0x1D,
            Self::Secp256r1 => 0x17,
            Self::Secp384r1 => 0x18,
            Self::X25519MLKEM768 => 0x11EC,
            Self::Grease(g) => g.grease,
            Self::Unknown(u) => u,
        }
    }
}

impl TryFrom<u16> for NamedGroup {
    type Error = TlsError;
    
    fn try_from(value: u16) -> TlsResult<Self> {
        match value {
            0x1D => Ok(Self::X25519),
            0x17 => Ok(Self::Secp256r1),
            0x18 => Ok(Self::Secp384r1),
            0x11EC => Ok(Self::X25519MLKEM768),
            _ => match GreasePayloadU16::is_grease(value) {
                Ok(g) => Ok(Self::Grease(g)),
                Err(_) => {
                    warn!("Unknown named group");
                    Ok(Self::Unknown(value))
                }
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
    pub fn to_unsupported(&self) -> NamedGroup {
        match self {
            Self::X25519 => NamedGroup::X25519,
            Self::Secp256R1 => NamedGroup::Secp256r1,
            Self::Secp384R1 => NamedGroup::Secp384r1,
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
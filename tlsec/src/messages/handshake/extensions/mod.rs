pub mod server;
pub mod client;

use crate::messages::*;

use server::*;
use client::*;

use super::*;

pub struct Extension {
    pub extension_type: ExtensionType,
    pub data: ExtensionPayload, // length = u16
}

impl Serialize for Extension {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.extension_type.into());

        let len_pos: usize = buf.len();
        buf.put_u16(0);

        self.data.encode_payload(buf);

        let len: u16 = (buf.len() - len_pos - 2) as u16;
        buf[len_pos..len_pos+2].copy_from_slice(&len.to_be_bytes())
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        let extension_type: ExtensionType = ExtensionType::try_from(buf.get_u16())?;
        let length: usize = buf.get_u16() as usize;

        if buf.remaining() < length {
            return Err(Error::Incomplete(length - buf.remaining()));
        }

        let mut data_buf: BytesMut = buf.split_to(length);
        let data: ExtensionPayload = ExtensionPayload::decode_payload(extension_type, &mut data_buf)?;

        Ok(Self {
            extension_type,
            data,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionType {
    Client(ClientExtensionType),
    Server(ServerExtensionType),
}

impl Into<u16> for ExtensionType {
    fn into(self) -> u16 {
        match self {
            Self::Client(typ) => typ as u16,
            Self::Server(typ) => typ as u16,
        }
    }
}

impl TryFrom<u16> for ExtensionType {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        if let Ok(typ) = ServerExtensionType::try_from(value) {
            return Ok(ExtensionType::Server(typ));
        }

        if let Ok(typ) = ClientExtensionType::try_from(value) {
            return Ok(ExtensionType::Client(typ));
        }
        
        Err(Error::Unknown("extension type"))
    }
}

pub enum ExtensionPayload {
    Client(ClientExtensionPayload),
    Server(ServerExtensionPayload),
}

impl ExtensionPayload {
    pub fn encode_payload(&self, buf: &mut BytesMut) {
        match self {
            Self::Client(typ) => typ.encode_payload(buf),
            Self::Server(typ) => typ.encode_payload(buf),
        }
    }

    pub fn decode_payload(extension_type: ExtensionType, buf: &mut BytesMut) -> Result<Self, Error> {
        match extension_type {
            ExtensionType::Client(z) => Ok(Self::Client(ClientExtensionPayload::decode_payload(z, buf)?)),
            ExtensionType::Server(z) => Ok(Self::Server(ServerExtensionPayload::decode_payload(z, buf)?)),
        }
    }
}

pub struct KeyShareEntry {
    pub group: NamedGroup,
    pub key_exchange: BytesMut, // length = u16
}

impl Serialize for KeyShareEntry {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.group as u16);
        buf.put_u16(self.key_exchange.len() as u16);
        buf.put_slice(&self.key_exchange);
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let group: NamedGroup = NamedGroup::try_from(buf.get_u16())?;
        
        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let key_len: usize = buf.get_u16() as usize;
        if buf.remaining() < key_len {
            return Err(Error::Incomplete(key_len - buf.remaining()));
        }

        let key_exchange: BytesMut = buf.split_to(key_len);
        
        Ok(Self { group, key_exchange })
    }
}

pub struct AlpnPayload {
    pub protocols: Vec<AlpnProtocol>, // length = u16
}

impl Serialize for AlpnPayload {
    fn encode(&self, buf: &mut BytesMut) {
        let mut inner: BytesMut = BytesMut::new();
        for proto in &self.protocols {
            proto.encode(&mut inner);
        }
        buf.put_u16(inner.len() as u16);
        buf.put_slice(&inner);
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let list_length: usize = buf.get_u16() as usize;

        if buf.remaining() < list_length {
            return Err(Error::Incomplete(list_length - buf.remaining()));
        }

        let mut data: BytesMut = buf.split_to(list_length);

        let mut protocols: Vec<AlpnProtocol> = Vec::new();

        while data.has_remaining() {
            protocols.push(AlpnProtocol::decode(&mut data)?);
        }

        Ok(Self { protocols })
    }
}

pub struct AlpnProtocol {
    pub name: AlpnProtocols, // length = u8
}

impl Serialize for AlpnProtocol {
    fn encode(&self, buf: &mut BytesMut) {
        let proto_bytes = match self.name {
            AlpnProtocols::Http11 => b"http/1.1" as &[u8],
            AlpnProtocols::H2 => b"h2" as &[u8],
            AlpnProtocols::H3 => b"h3" as &[u8],
        };
        buf.put_u8(proto_bytes.len() as u8);
        buf.put_slice(proto_bytes);
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 1 {
            return Err(Error::Incomplete(1 - buf.remaining()));
        }

        let len: usize = buf.get_u8() as usize;

        if buf.remaining() < len {
            return Err(Error::Incomplete(len - buf.remaining()));
        }

        let name: AlpnProtocols = AlpnProtocols::try_from(buf.split_to(len))?;

        Ok(Self { name })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlpnProtocols {
    Http11,
    H2,
    H3,
}

impl TryFrom<BytesMut> for AlpnProtocols {
    type Error = Error;

    fn try_from(value: BytesMut) -> Result<Self, Self::Error> {
        match value.as_ref() {
            b"http/1.1" => Ok(AlpnProtocols::Http11),
            b"h2" => Ok(AlpnProtocols::H2),
            b"h3" => Ok(AlpnProtocols::H3),
            _ => Err(Error::Unknown("ALPN")),
        }
    }
}

impl AsRef<[u8]> for AlpnProtocols {
    fn as_ref(&self) -> &[u8] {
        match self {
            AlpnProtocols::Http11 => b"http/1.1",
            AlpnProtocols::H2 => b"h2",
            AlpnProtocols::H3 => b"h3",
        }
    }
}
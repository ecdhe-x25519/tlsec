use crate::message::*;
use crate::error::*;

use bytes::*;

pub struct Extension {
    pub extension_type: ExtensionType,
    pub payload: ExtensionPayload, // length = u16
}

impl Serialize for Extension {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.extension_type.into());

        let len_pos: usize = buf.len();
        buf.put_u16(0);

        self.payload.encode_payload(buf);

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
        let payload: ExtensionPayload = ExtensionPayload::decode_payload(extension_type, &mut data_buf)?;

        Ok(Self {
            extension_type,
            payload,
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

#[cfg(test)]
mod test_extension_parse {
    
}
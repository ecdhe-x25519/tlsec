use crate::message::*;
use crate::error::*;

use bytes::*;

pub struct ServerNamePayload {
    pub name_type: NameType,
    pub name: String, // length = u16
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum NameType {
    HostName = 0x00,
}

impl TryFrom<u8> for NameType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::HostName),
            _ => Err(Error::Unknown("name type")),
        }
    }
}

impl Serialize for ServerNamePayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.name_type as u8);
        buf.put_u16(self.name.len() as u16);
        buf.put(BytesMut::from(self.name.as_str()));
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 1 {
            return Err(Error::Incomplete(1 - buf.remaining()))
        }

        let name_type: NameType = NameType::try_from(buf.get_u8())?;

        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()))
        }

        let name_length: usize = buf.get_u16() as usize;

        if buf.remaining() < name_length {
            return Err(Error::Incomplete(name_length - buf.remaining()))
        }

        let bytes: BytesMut = buf.split_to(name_length);
        let name: String = String::from_utf8(bytes.to_vec())
            .map_err(|e| Error::Io(format!("wrong sni: {e}")))?;

        Ok(Self {
            name_type,
            name,
        })
    }
}

#[cfg(test)]
mod test_client_psk_parse {
    
}
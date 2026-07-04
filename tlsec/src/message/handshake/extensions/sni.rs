use crate::{error::*, message::serialize::Serialize};

use bytes::*;
use brevno::*;

#[derive(Debug, PartialEq, Eq)]
pub struct ServerNamePayload {
    pub name_type: NameType,
    pub name: String, // length = u16
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameType {
    HostName = 0x00,
}

impl TryFrom<u8> for NameType {
    type Error = TlsError;

    fn try_from(value: u8) -> TlsResult<Self> {
        match value {
            0x00 => Ok(Self::HostName),
            _ => {
                warn!("Unknown SNI name type");
                Err(TlsError::Unknown("name type"))
            }
        }
    }
}

impl Serialize for ServerNamePayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.name_type as u8);
        buf.put_u16(self.name.len() as u16);
        buf.put(BytesMut::from(self.name.as_str()));
    }

    fn decode(buf: &mut BytesMut) -> TlsResult<Self> {
        if buf.remaining() < 3 {
            error!(format!("Incomplete data: need {} more bytes", (3 - buf.remaining())));
            return Err(TlsError::Incomplete(3 - buf.remaining()))
        }

        let name_type: NameType = NameType::try_from(buf.get_u8())?;

        let name_length: usize = buf.get_u16() as usize;

        if buf.remaining() < name_length {
            error!(format!("Incomplete data: need {} more bytes", (name_length - buf.remaining())));
            return Err(TlsError::Incomplete(name_length - buf.remaining()))
        }

        let bytes: BytesMut = buf.split_to(name_length);
        let name: String = String::from_utf8(bytes.to_vec())
            .map_err(|e| TlsError::Io(format!("wrong sni: {e}")))?;

        Ok(Self {
            name_type,
            name,
        })
    }
}
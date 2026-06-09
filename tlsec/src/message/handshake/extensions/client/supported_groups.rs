use crate::message::serialize::Serialize;
use crate::message::handshake::extensions::key_share::NamedGroup;

use crate::error::TlsError;

use bytes::*;

#[derive(Debug, PartialEq, Eq)]
pub struct SupportedGroupsPayload {
    pub groups: Vec<NamedGroup>, // length = u16
}

impl Serialize for SupportedGroupsPayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16((self.groups.len() * 2) as u16);
        for group in &self.groups {
            buf.put_u16(*group as u16);
        }
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, TlsError> {
        if buf.remaining() < 2 {
            return Err(TlsError::Incomplete(2 - buf.remaining()))
        }

        let list_length: usize = buf.get_u16() as usize;

        if buf.remaining() < list_length {
            return Err(TlsError::Incomplete(list_length - buf.remaining()))
        }

        let mut groups: Vec<NamedGroup> = Vec::new();
        for _ in 0..list_length / 2 {
            groups.push(NamedGroup::try_from(buf.get_u16())?);
        }

        Ok(Self {
            groups,
        })
    }
}

#[cfg(test)]
mod test_client_sg_parse {
    
}
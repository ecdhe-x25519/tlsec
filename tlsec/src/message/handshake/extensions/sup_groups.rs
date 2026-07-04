use crate::{error::*, message::{handshake::extensions::key_share::NamedGroup, serialize::Serialize}};

use bytes::*;
use brevno::*;

#[derive(Debug, PartialEq, Eq)]
pub struct SupportedGroupsPayload {
    pub groups: Vec<NamedGroup>, // length = u16
}

impl Serialize for SupportedGroupsPayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16((self.groups.len() * 2) as u16);
        for group in &self.groups {
            buf.put_u16((*group).into());
        }
    }

    fn decode(buf: &mut BytesMut) -> TlsResult<Self> {
        if buf.remaining() < 2 {
            error!(format!("Incomplete data: need {} more bytes", (2 - buf.remaining())));
            return Err(TlsError::Incomplete(2 - buf.remaining()))
        }

        let list_length: usize = buf.get_u16() as usize;

        if buf.remaining() < list_length {
            error!(format!("Incomplete data: need {} more bytes", (list_length - buf.remaining())));
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
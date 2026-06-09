use crate::message::serialize::Serialize;
use crate::message::handshake::extensions::key_share::KeyShareEntry;
use crate::message::handshake::extensions::key_share::NamedGroup;

use crate::error::TlsError;

use bytes::*;

#[derive(Debug, PartialEq, Eq)]
pub struct KeyShareServer {
    pub server_share: KeyShareEntry,
}

impl Serialize for KeyShareServer {
    fn encode(&self, buf: &mut BytesMut) {
        self.server_share.encode(buf);
    }
    
    fn decode(buf: &mut BytesMut) -> Result<Self, TlsError> {
        let server_share: KeyShareEntry = KeyShareEntry::decode(buf)?;
        Ok(Self { server_share })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct KeyShareHelloRetryRequest {
    pub selected_group: NamedGroup,
}

impl Serialize for KeyShareHelloRetryRequest {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.selected_group as u16);
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, TlsError> {
        if buf.remaining() < 2 {
            return Err(TlsError::Incomplete(2 - buf.remaining()));
        }

        let selected_group: NamedGroup = NamedGroup::try_from(buf.get_u16())?;

        Ok(Self { selected_group })
    }
}

#[cfg(test)]
mod test_server_ks_parse {
    
}
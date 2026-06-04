use crate::message::serialize::Serialize;
use crate::message::handshake::extensions::alpn::AlpnProtocols;

use crate::error::Error;

use bytes::*;

#[derive(Debug, PartialEq, Eq)]
pub struct ApplicationSettingsPayload {
    pub protocol: AlpnProtocols, // length = u8
    pub settings: Bytes, // length = u16
}

impl Serialize for ApplicationSettingsPayload {
    fn encode(&self, buf: &mut BytesMut) {
        let proto_bytes = self.protocol.as_ref();
        buf.put_u8(proto_bytes.len() as u8);
        buf.put_slice(proto_bytes);
        buf.put_u16(self.settings.len() as u16);
        buf.put_slice(&self.settings);
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 1 {
            return Err(Error::Incomplete(1 - buf.remaining()));
        }

        let proto_len: usize = buf.get_u8() as usize;

        if buf.remaining() < proto_len {
            return Err(Error::Incomplete(proto_len - buf.remaining()));
        }

        let protocol_bytes: BytesMut = buf.split_to(proto_len);

        let protocol: AlpnProtocols = AlpnProtocols::try_from(protocol_bytes)?;
        
        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let settings_len: usize = buf.get_u16() as usize;

        if buf.remaining() < settings_len {
            return Err(Error::Incomplete(settings_len - buf.remaining()));
        }

        let settings: Bytes = buf.split_to(settings_len).freeze();
        
        Ok(Self { protocol, settings })
    }
}

#[cfg(test)]
mod test_client_as_parse {
    
}
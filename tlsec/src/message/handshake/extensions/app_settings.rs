use crate::{error::*, message::{handshake::extensions::alpn::AlpnProtocols, serialize::Serialize}};

use bytes::*;
use brevno::*;

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

    fn decode(buf: &mut BytesMut) -> TlsResult<Self> {
        if buf.remaining() < 1 {
            error!(format!("Incomplete data: need {} more bytes", (1 - buf.remaining())));
            return Err(TlsError::Incomplete(1 - buf.remaining()));
        }

        let proto_len: usize = buf.get_u8() as usize;

        if buf.remaining() < proto_len + 2 {
            error!(format!("Incomplete data: need {} more bytes", (proto_len + 2 - buf.remaining())));
            return Err(TlsError::Incomplete(proto_len + 2 - buf.remaining()));
        }

        let protocol_bytes: BytesMut = buf.split_to(proto_len);

        let protocol: AlpnProtocols = AlpnProtocols::try_from(protocol_bytes)?;

        let settings_len: usize = buf.get_u16() as usize;

        if buf.remaining() < settings_len {
            error!(format!("Incomplete data: need {} more bytes", (settings_len - buf.remaining())));
            return Err(TlsError::Incomplete(settings_len - buf.remaining()));
        }

        let settings: Bytes = buf.split_to(settings_len).freeze();
        
        Ok(Self { protocol, settings })
    }
}
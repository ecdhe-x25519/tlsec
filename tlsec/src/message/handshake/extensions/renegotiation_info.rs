use crate::{error::*, message::serialize::Serialize};

use bytes::*;

use brevno::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenegotiationInfoPayload {
    pub renegotiated_connection: Bytes,
}

impl Serialize for RenegotiationInfoPayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.renegotiated_connection.len() as u8);
        buf.put_slice(&self.renegotiated_connection);
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, TlsError> {
        if buf.remaining() == 0 {
            return Ok(Self { renegotiated_connection: Bytes::new() })
        }

        if buf.remaining() < 1 {
            error!(format!("Incomplete data: need {} more bytes", (1 - buf.remaining())));
            return Err(TlsError::Incomplete(1 - buf.remaining()));
        }

        let len = buf.get_u8() as usize;

        if len > 255 {
            error!("Invalid length");
            return Err(TlsError::Io("invalid length".to_string()));
        }

        if buf.remaining() < len {
            error!(format!("Incomplete data: need {} more bytes", (len - buf.remaining())));
            return Err(TlsError::Incomplete(len - buf.remaining()));
        }

        let renegotiated_connection = buf.split_to(len).freeze();

        Ok(RenegotiationInfoPayload { renegotiated_connection })
    }
}
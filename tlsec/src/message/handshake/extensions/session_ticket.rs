use crate::{error::*, message::serialize::Serialize};

use bytes::*;

use brevno::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTicketPayload {
    pub ticket: Bytes,
}

impl Serialize for SessionTicketPayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.ticket.len() as u16);
        buf.put_slice(&self.ticket);
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, TlsError> {
        if buf.remaining() == 0 {
            return Ok(Self { ticket: Bytes::new() });
        }

        if buf.remaining() < 2 {
            error!(format!("Incomplete data: need {} more bytes", (2 - buf.remaining())));
            return Err(TlsError::Incomplete(2 - buf.remaining()));
        }
        
        let len = buf.get_u16() as usize;

        if buf.remaining() < len {
            error!(format!("Incomplete data: need {} more bytes", (len - buf.remaining())));
            return Err(TlsError::Incomplete(len - buf.remaining()));
        }

        let ticket = buf.split_to(len).freeze();
        Ok(SessionTicketPayload { ticket })
    }
}
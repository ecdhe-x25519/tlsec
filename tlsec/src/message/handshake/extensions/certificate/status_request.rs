use crate::message::*;
use crate::error::*;

use bytes::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusRequestPayload {
    pub status_type: StatusType,
    pub responder_id_list: Bytes, // length = u16
    pub request_extensions: Bytes, // length = u16
}

impl Serialize for StatusRequestPayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.status_type as u8);
        buf.put_u16(self.responder_id_list.len() as u16);
        buf.put_slice(&self.responder_id_list);
        buf.put_u16(self.request_extensions.len() as u16);
        buf.put_slice(&self.request_extensions);
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 1 {
            return Err(Error::Incomplete(1 - buf.remaining()));
        }

        let status_type: StatusType = StatusType::try_from(buf.get_u8())?;
        
        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let responder_len: usize = buf.get_u16() as usize;

        if buf.remaining() < responder_len {
            return Err(Error::Incomplete(responder_len - buf.remaining()));
        }

        let responder_id_list: Bytes = buf.split_to(responder_len).freeze();
        
        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let ext_len: usize = buf.get_u16() as usize;

        if buf.remaining() < ext_len {
            return Err(Error::Incomplete(ext_len - buf.remaining()));
        }

        let request_extensions: Bytes = buf.split_to(ext_len).freeze();
        
        Ok(Self {
            status_type,
            responder_id_list,
            request_extensions,
        })
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusType {
    Ocsp = 0x01,
}

impl TryFrom<u8> for StatusType {
    type Error = Error;
    
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(StatusType::Ocsp),
            _ => Err(Error::Unknown("status type")),
        }
    }
}

#[cfg(test)]
mod test_status_request_parse {
    
}
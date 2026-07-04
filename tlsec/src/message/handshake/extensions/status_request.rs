use crate::message::serialize::Serialize;

use crate::error::*;

use bytes::*;

use brevno::*;

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

    fn decode(buf: &mut BytesMut) -> TlsResult<Self> {
        if buf.remaining() < 3 {
            error!(format!("Incomplete data: need {} more bytes", (1 - buf.remaining())));
            return Err(TlsError::Incomplete(1 - buf.remaining()));
        }

        let status_type: StatusType = StatusType::try_from(buf.get_u8())?;

        let responder_len: usize = buf.get_u16() as usize;

        if buf.remaining() < responder_len + 2 {
            return Err(TlsError::Incomplete(responder_len + 2 - buf.remaining()));
        }

        let responder_id_list: Bytes = buf.split_to(responder_len).freeze();

        let ext_len: usize = buf.get_u16() as usize;

        if buf.remaining() < ext_len {
            error!(format!("Incomplete data: need {} more bytes", (ext_len - buf.remaining())));
            return Err(TlsError::Incomplete(ext_len - buf.remaining()));
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
    type Error = TlsError;
    
    fn try_from(value: u8) -> TlsResult<Self> {
        match value {
            0x01 => Ok(StatusType::Ocsp),
            _ => {
                warn!("Unknown status type");
                Err(TlsError::Unknown("status type"))
            }
        }
    }
}

#[cfg(test)]
mod test_status_request_parse {
    
}
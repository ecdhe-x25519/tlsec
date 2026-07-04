use crate::message::serialize::Serialize;
use crate::message::handshake::extensions::*;

use crate::error::*;

use bytes::*;

use brevno::*;

#[derive(Debug, PartialEq, Eq)]
pub struct EncryptedExtensionsPayload {
    pub extensions: Vec<Extension>, // length = u16
}

impl Serialize for EncryptedExtensionsPayload {
    fn encode(&self, buf: &mut BytesMut) {
        let len_pos: usize = buf.len();
        buf.put_u16(0);

        for ext in &self.extensions {
            ext.encode(buf);
        }
        
        let len: u16 = (buf.len() - len_pos - 2) as u16;
        buf[len_pos..len_pos+2].copy_from_slice(&len.to_be_bytes());
    }

    fn decode(buf: &mut BytesMut) -> TlsResult<Self> {
        if buf.remaining() < 2 {
            error!(format!("Incomplete data: need {} more bytes", (2 - buf.remaining())));
            return Err(TlsError::Incomplete(2 - buf.remaining()));
        }

        let length: usize = buf.get_u16() as usize;

        if buf.remaining() < length {
            error!(format!("Incomplete data: need {} more bytes", (length - buf.remaining())));
            return Err(TlsError::Incomplete(length - buf.remaining()));
        }

        let mut ext_buf: BytesMut = buf.split_to(length);
        let mut extensions: Vec<Extension> = Vec::new();
        while ext_buf.remaining() > 0 {
            extensions.push(Extension::decode(&mut ext_buf)?);
        }

        Ok(Self {
            extensions,
        })
    }
}

#[cfg(test)]
mod test_ech_parse {
    
}
use crate::message::{
    record::RecordType,
    version::Version,
};

use crate::error::*;

use bytes::*;

const TLS_RECORD_HEADER_SIZE: usize = 5;

#[derive(Debug)]
pub struct OuterMessage {
    pub(crate) typ: RecordType,
    pub(crate) version: Version,
    pub(crate) ciphertext: BytesMut,
}

impl OuterMessage {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.typ as u8);
        buf.put_u16(self.version.into());
        buf.put_u16(self.ciphertext.len() as u16);
        buf.extend_from_slice(&self.ciphertext);
    }
}

pub struct MessageDeframer {
    pub(crate) buffer: BytesMut,
}

impl MessageDeframer {
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: BytesMut::with_capacity(capacity),
        }
    }

    pub fn pop(&mut self) -> TlsResult<Option<OuterMessage>> {
        let buf = &mut self.buffer;

        if buf.len() < TLS_RECORD_HEADER_SIZE {
            return Ok(None);
        };

        let typ = RecordType::try_from(buf.get_u8())?;
        let version = Version::try_from(buf.get_u16())?;
        let len = buf.get_u16() as usize;

        if buf.remaining() < len {
            return Ok(None);
        }

        let ciphertext = buf.split_to(len);

        Ok(Some(OuterMessage {
            typ,
            version,
            ciphertext,
        }))
    }

    pub fn write(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data)
    }
}
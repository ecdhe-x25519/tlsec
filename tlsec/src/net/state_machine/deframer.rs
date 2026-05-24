use crate::messages::record::RecordType;
use crate::messages::Version;

use crate::error::Error;

use crate::messages::record::AlertDescription;

use bytes::{BytesMut, BufMut, Buf};

pub const TLS_RECORD_HEADER_SIZE: usize = 5;

pub struct OpaqueMessage {
    pub typ: RecordType,
    pub version: Version,
    pub payload: BytesMut,
}

impl OpaqueMessage {
    pub fn into_bytes(self) -> BytesMut {
        let mut buf: BytesMut = BytesMut::with_capacity(TLS_RECORD_HEADER_SIZE + self.payload.len());
        buf.put_u8(self.typ as u8);
        buf.put_u16(self.version as u16);
        buf.put_u16(self.payload.len() as u16);
        buf.put_slice(&self.payload);
        buf
    }
}

pub struct PlainMessage {
    pub typ: RecordType,
    pub version: Version,
    pub payload: BytesMut,
}

impl PlainMessage {
    pub fn into_bytes(self) -> BytesMut {
        let mut buf: BytesMut = BytesMut::with_capacity(TLS_RECORD_HEADER_SIZE + self.payload.len());
        buf.put_u8(self.typ as u8);
        buf.put_u16(self.version as u16);
        buf.put_u16(self.payload.len() as u16);
        buf.put_slice(&self.payload);
        buf
    }
}

pub struct MessageDeframer {
    buffer: BytesMut,
}

impl MessageDeframer {
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(16384),
        }
    }
    
    pub fn extend(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }
    
    pub fn pop(&mut self) -> Result<Option<OpaqueMessage>, Error> {
        if self.buffer.len() < TLS_RECORD_HEADER_SIZE {
            return Ok(None);
        }
        
        let typ: RecordType = match RecordType::try_from(self.buffer[0]) {
            Ok(t) => t,
            Err(_) => return Err(Error::Alert(AlertDescription::UnexpectedMessage)),
        };
        
        let version: u16 = u16::from_be_bytes([self.buffer[1], self.buffer[2]]);
        let len: usize = u16::from_be_bytes([self.buffer[3], self.buffer[4]]) as usize;
        
        if self.buffer.len() < TLS_RECORD_HEADER_SIZE + len {
            return Ok(None);
        }
        
        let data: BytesMut = self.buffer.split_to(TLS_RECORD_HEADER_SIZE + len);
        let mut payload: BytesMut = data;
        
        payload.advance(TLS_RECORD_HEADER_SIZE);
        
        Ok(Some(OpaqueMessage {
            typ,
            version: Version::try_from(version)?,
            payload,
        }))
    }
    
    pub fn has_pending(&self) -> bool {
        !self.buffer.is_empty()
    }
    
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}
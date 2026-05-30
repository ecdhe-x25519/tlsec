use crate::message::*;
use crate::error::*;

use bytes::*;

pub struct EncryptedClientHelloPayload {
    pub data: Bytes,
}

impl Serialize for EncryptedClientHelloPayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_slice(&self.data);
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        let data: Bytes = buf.split_to(buf.remaining()).freeze();
        Ok(Self { data })
    }
}

#[cfg(test)]
mod test_client_ech_parse {
    
}
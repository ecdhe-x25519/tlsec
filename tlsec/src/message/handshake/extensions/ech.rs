use crate::{error::*, message::serialize::Serialize};

use bytes::*;

#[derive(Debug, PartialEq, Eq)]
pub struct EncryptedClientHelloPayload {
    pub data: Bytes,
}

impl Serialize for EncryptedClientHelloPayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_slice(&self.data);
    }

    fn decode(buf: &mut BytesMut) -> TlsResult<Self> {
        let data: Bytes = buf.split_to(buf.remaining()).freeze();
        Ok(Self { data })
    }
}
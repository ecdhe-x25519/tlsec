use crate::error::*;

use bytes::*;

pub(crate) trait Serialize: Sized {
    fn encode(&self, buf: &mut BytesMut);
    fn decode(buf: &mut BytesMut) -> TlsResult<Self>;
}
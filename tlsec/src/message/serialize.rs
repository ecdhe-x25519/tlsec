use crate::error::*;

use bytes::*;

pub trait Serialize: Sized {
    fn encode(&self, buf: &mut BytesMut);
    fn decode(buf: &mut BytesMut) -> Result<Self, Error>;
}
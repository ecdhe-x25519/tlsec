pub mod record;
pub mod handshake;

use crate::error::Error;

use bytes::{Buf, BytesMut, BufMut};

pub trait Serialize: Sized {
    fn encode(&self, buf: &mut BytesMut);
    fn decode(buf: &mut BytesMut) -> Result<Self, Error>;
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    Tls10 = 0x0301,
    Tls11 = 0x0302,
    Tls12 = 0x0303,
    Tls13 = 0x0304,
}

impl TryFrom<u16> for Version {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Error> {
        match value {
            0x0301 => Ok(Self::Tls10),
            0x0302 => Ok(Self::Tls11),
            0x0303 => Ok(Self::Tls12),
            0x0304 => Ok(Self::Tls13),
            _ => Err(Error::UnsupportedVersion),
        }
    }
}
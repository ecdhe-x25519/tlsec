use crate::message::*;
use crate::error::*;

use bytes::*;

pub struct SupportedVersionsClient {
    pub versions: Vec<Version>, // length = u8
}

impl Serialize for SupportedVersionsClient {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8((self.versions.len() * 2) as u8);
        for v in &self.versions {
            buf.put_u16(*v as u16);
        }
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 1 {
            return Err(Error::Incomplete(1 - buf.remaining()));
        }

        let list_length: usize = buf.get_u8() as usize;

        if buf.remaining() < list_length {
            return Err(Error::Incomplete(list_length - buf.remaining()));
        }

        let mut versions: Vec<Version> = Vec::new();

        for _ in 0..list_length / 2 {
            versions.push(Version::try_from(buf.get_u16())?);
        }

        Ok(Self { versions })
    }
}

#[cfg(test)]
mod test_client_sv_parse {
    
}
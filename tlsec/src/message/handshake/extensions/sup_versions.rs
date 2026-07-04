use crate::{error::*, message::{serialize::Serialize, version::Version}};

use bytes::*;
use brevno::*;

#[derive(Debug, PartialEq, Eq)]
pub struct SupportedVersionsPayload {
    pub versions: Vec<Version>, // length = u8
}

impl Serialize for SupportedVersionsPayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8((self.versions.len() * 2) as u8);
        for v in &self.versions {
            buf.put_u16((*v).into());
        }
    }

    fn decode(buf: &mut BytesMut) -> TlsResult<Self> {
        if buf.remaining() < 1 {
            error!(format!("Incomplete data: need {} more bytes", (1 - buf.remaining())));
            return Err(TlsError::Incomplete(1 - buf.remaining()));
        }

        let list_length: usize = buf.get_u8() as usize;

        if buf.remaining() < list_length {
            error!(format!("Incomplete data: need {} more bytes", (list_length - buf.remaining())));
            return Err(TlsError::Incomplete(list_length - buf.remaining()));
        }

        let mut versions: Vec<Version> = Vec::new();

        for _ in 0..list_length / 2 {
            versions.push(Version::try_from(buf.get_u16())?);
        }

        Ok(Self { versions })
    }
}
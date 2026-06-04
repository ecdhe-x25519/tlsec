use crate::message::serialize::Serialize;
use crate::message::version::Version;

use crate::error::Error;

use bytes::*;

#[derive(Debug, PartialEq, Eq)]
pub struct SupportedVersionsServer {
    pub selected_version: Version,
}

impl Serialize for SupportedVersionsServer {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.selected_version as u16);
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let selected_version: Version = Version::try_from(buf.get_u16())?;

        Ok(Self { selected_version })
    }
}

#[cfg(test)]
mod test_server_sv_parse {
    
}
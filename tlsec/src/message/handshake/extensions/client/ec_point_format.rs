use crate::message::serialize::Serialize;

use crate::error::Error;

use bytes::*;

#[derive(Debug, PartialEq, Eq)]
pub struct EcPointFormatsPayload {
    pub formats: Vec<EcPointFormat>, // length = u8
}

impl Serialize for EcPointFormatsPayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.formats.len() as u8);
        for format in &self.formats {
            buf.put_u8(*format as u8);
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

        let mut formats: Vec<EcPointFormat> = Vec::new();

        for _ in 0..list_length {
            formats.push(EcPointFormat::try_from(buf.get_u8())?);
        }

        Ok(Self { formats })
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcPointFormat {
    Uncompressed = 0x00,
    AnsiX962CompressedPrime = 0x01,
    AnsiX962CompressedChar2 = 0x02,
}

impl TryFrom<u8> for EcPointFormat {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Uncompressed),
            0x01 => Ok(Self::AnsiX962CompressedPrime),
            0x02 => Ok(Self::AnsiX962CompressedChar2),
            _ => Err(Error::Unknown("EC point format"))
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SupportedEcPointFormat {
    Uncompressed,
}

impl SupportedEcPointFormat {
    pub fn compare(&self, format: &EcPointFormat) -> Option<SupportedEcPointFormat> {
        match format {
            EcPointFormat::Uncompressed => Some(Self::Uncompressed),
            _ => None,
        }
    }
}

#[cfg(test)]
mod test_client_ecpf_parse {
    
}
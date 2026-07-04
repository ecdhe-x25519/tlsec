use crate::{error::*, message::serialize::Serialize};

use bytes::*;
use brevno::*;

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

impl EcPointFormat {
    pub fn to_supported(&self) -> Option<SupportedEcPointFormat> {
        match self {
            EcPointFormat::Uncompressed => Some(SupportedEcPointFormat::Uncompressed),
            _ => None,
        }
    }
}

impl TryFrom<u8> for EcPointFormat {
    type Error = TlsError;

    fn try_from(value: u8) -> TlsResult<Self> {
        match value {
            0x00 => Ok(Self::Uncompressed),
            0x01 => Ok(Self::AnsiX962CompressedPrime),
            0x02 => Ok(Self::AnsiX962CompressedChar2),
            _ => {
                warn!("Unknown EC point format");
                Err(TlsError::Unknown("EC point format"))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedEcPointFormat {
    Uncompressed,
}
use crate::{error::*, message::serialize::Serialize};

use bytes::*;
use brevno::*;

#[derive(Debug, PartialEq, Eq)]
pub struct PskKeyExchangeModesPayload {
    pub modes: Vec<PskKeyExchangeMode>, // length = u8
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PskKeyExchangeMode {
    PskKe = 0x00,
    PskDheKe = 0x01,
}

impl TryFrom<u8> for PskKeyExchangeMode {
    type Error = TlsError;

    fn try_from(value: u8) -> TlsResult<Self> {
        match value {
            0x00 => Ok(Self::PskKe),
            0x01 => Ok(Self::PskDheKe),
            _ => Err(TlsError::Unknown("PSK exchange mode"))
        }
    }
}

impl Serialize for PskKeyExchangeModesPayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.modes.len() as u8);
        for mode in &self.modes {
            buf.put_u8(*mode as u8);
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

        let mut modes: Vec<PskKeyExchangeMode> = Vec::new();

        for _ in 0..list_length {
            modes.push(PskKeyExchangeMode::try_from(buf.get_u8())?);
        }

        Ok(Self { modes })
    }
}
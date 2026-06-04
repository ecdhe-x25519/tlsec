use crate::message::serialize::Serialize;

use crate::error::Error;

use bytes::*;

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
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::PskKe),
            0x01 => Ok(Self::PskDheKe),
            _ => Err(Error::Unknown("PSK exchange mode"))
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

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 1 {
            return Err(Error::Incomplete(1 - buf.remaining()));
        }
        
        let list_length: usize = buf.get_u8() as usize;

        if buf.remaining() < list_length {
            return Err(Error::Incomplete(list_length - buf.remaining()));
        }

        let mut modes: Vec<PskKeyExchangeMode> = Vec::new();

        for _ in 0..list_length {
            modes.push(PskKeyExchangeMode::try_from(buf.get_u8())?);
        }

        Ok(Self { modes })
    }
}

#[cfg(test)]
mod test_client_psk_mode_parse {
    
}
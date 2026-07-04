use bytes::{BufMut, BytesMut};

use crate::error::*;

use crate::encryption::random::ochkagen;

const GREASE_U8_VALUES: [u8; 16] = [
    0x0A, 0x1A, 0x2A, 0x3A, 0x4A, 0x5A, 0x6A, 0x7A,
    0x8A, 0x9A, 0xAA, 0xBA, 0xCA, 0xDA, 0xEA, 0xFA,
];

const GREASE_U16_VALUES: [u16; 16] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GreasePayloadU8 {
    pub grease: u8
}

impl GreasePayloadU8 {
    pub fn new() -> TlsResult<Self> {
        let mut idx: [u8; 1] = [0u8; 1];
        ochkagen(&mut idx)
            .map_err(|e| TlsError::Crypto(format!("RNG failed: {e}")))?;

        let grease = GREASE_U8_VALUES[(idx[0] as usize) % 8];

        Ok(Self{ grease })
    }

    pub fn is_grease(value: u8) -> TlsResult<Self> {
        if (value & 0x0F) == 0x0A {
            return Ok(Self { grease: value })
        }

        Err(TlsError::Alert(AlertDescription::IllegalParameter))
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.grease);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GreasePayloadU16 {
    pub grease: u16
}

impl GreasePayloadU16 {
    pub fn new() -> TlsResult<Self> {
        let mut idx: [u8; 1] = [0u8; 1];
        ochkagen(&mut idx)
            .map_err(|e| TlsError::Crypto(format!("RNG failed: {e}")))?;

        let grease = GREASE_U16_VALUES[(idx[0] as usize) % 16];
        
        Ok(Self{ grease })
    }

    pub fn is_grease(value: u16) -> TlsResult<Self> {
        let b1: u8 = (value >> 8) as u8;
        let b2: u8 = (value & 0xFF) as u8;

        if b1 == b2 && (b1 & 0x0F) == 0x0A {
            return Ok(Self { grease: value })
        }

        Err(TlsError::Alert(AlertDescription::IllegalParameter))
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.grease);
    }
}

#[cfg(test)]
mod test_grease_parse {
    use super::*;

    #[test]
    fn test_grease_u8() {
        for _ in 0..100 {
            let val = GreasePayloadU8::new().unwrap().grease;
            assert!(GreasePayloadU8::is_grease(val).is_ok());
            assert!(GREASE_U8_VALUES.contains(&val));
        }
    }

    #[test]
    fn test_grease_u16() {
        for _ in 0..100 {
            let val = GreasePayloadU16::new().unwrap().grease;
            assert!(GreasePayloadU16::is_grease(val).is_ok());
            assert!(GREASE_U16_VALUES.contains(&val));
        }
    }
}
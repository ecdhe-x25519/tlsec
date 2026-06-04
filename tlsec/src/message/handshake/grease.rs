use crate::error::*;

use crate::encryption::random::Random;

pub const GREASE_U8_VALUES: [u8; 16] = [
    0x0A, 0x1A, 0x2A, 0x3A, 0x4A, 0x5A, 0x6A, 0x7A,
    0x8A, 0x9A, 0xAA, 0xBA, 0xCA, 0xDA, 0xEA, 0xFA,
];

pub const GREASE_U16_VALUES: [u16; 16] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

pub fn grease_u8(rng: &Random) -> Result<u8, Error> {
    let mut idx: [u8; 1] = [0u8; 1];
    rng.ochkagen(&mut idx).map_err(|e| Error::Crypto(format!("RNG failed: {e}")))?;
    Ok(GREASE_U8_VALUES[(idx[0] as usize) % 8])
}

pub fn grease_u16(rng: &Random) -> Result<u16, Error> {
    let mut idx: [u8; 1] = [0u8; 1];
    rng.ochkagen(&mut idx).map_err(|e| Error::Crypto(format!("RNG failed: {e}")))?;
    Ok(GREASE_U16_VALUES[(idx[0] as usize) % 16])
}

pub fn is_grease_u8(value: u8) -> bool {
    (value & 0x0F) == 0x0A
}

pub fn is_grease_u16(value: u16) -> bool {
    let b1: u8 = (value >> 8) as u8;
    let b2: u8 = (value & 0xFF) as u8;
    b1 == b2 && (b1 & 0x0F) == 0x0A
}

#[cfg(test)]
mod test_grease_parse {
    
}
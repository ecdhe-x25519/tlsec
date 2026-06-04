use crate::message::serialize::Serialize;

use crate::error::Error;

use bytes::*;

#[derive(Debug, PartialEq, Eq)]
pub struct CompressCertificatePayload {
    pub algorithms: Vec<CompressionAlgorithm>, // length = u8
}

impl Serialize for CompressCertificatePayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.algorithms.len() as u8);
        for alg in &self.algorithms {
            buf.put_u16(*alg as u16);
        }
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 1 {
            return Err(Error::Incomplete(1 - buf.remaining()));
        }

        let list_length: usize = buf.get_u8() as usize;

        if buf.remaining() < list_length * 2 {
            return Err(Error::Incomplete(list_length * 2 - buf.remaining()));
        }

        let mut algorithms: Vec<CompressionAlgorithm> = Vec::new();

        for _ in 0..list_length {
            algorithms.push(CompressionAlgorithm::try_from(buf.get_u8())?);
        }

        Ok(Self { algorithms })
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionAlgorithm {
    Zlib = 0x01,
    Brotli = 0x02,
}

impl TryFrom<u8> for CompressionAlgorithm {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Zlib),
            0x02 => Ok(Self::Brotli),
            _ => Err(Error::Unknown("compression algorithm"))
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SupportedCompressionAlgorithm {
    Zlib,
    Brotli,
}

impl SupportedCompressionAlgorithm {
    pub fn compare(&self, algorithm: &CompressionAlgorithm) -> Option<SupportedCompressionAlgorithm> {
        match algorithm {
            CompressionAlgorithm::Zlib => Some(Self::Zlib),
            CompressionAlgorithm::Brotli => Some(Self::Brotli),
        }
    }
}

#[cfg(test)]
mod test_compression_algo_parse {
    
}
use crate::{error::*, message::serialize::Serialize};

use bytes::*;
use brevno::*;

#[derive(Debug, PartialEq, Eq)]
pub struct CompressCertificatePayload {
    pub algorithms: Vec<CompressionAlgorithm>, // length = u8
}

impl Serialize for CompressCertificatePayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.algorithms.len() as u8);
        for alg in &self.algorithms {
            buf.put_u8((*alg).into());
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

        let mut algorithms: Vec<CompressionAlgorithm> = Vec::new();

        for _ in 0..list_length {
            algorithms.push(CompressionAlgorithm::try_from(buf.get_u8())?);
        }

        Ok(Self { algorithms })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionAlgorithm {
    Zlib,
    Brotli,
    Unknown(u8)
}

impl CompressionAlgorithm {
    pub fn to_supported(&self) -> Option<SupportedCompressionAlgorithm> {
        match self {
            Self::Zlib => Some(SupportedCompressionAlgorithm::Zlib),
            Self::Brotli => Some(SupportedCompressionAlgorithm::Brotli),
            _ => None,
        }
    }
}

impl Into<u8> for CompressionAlgorithm {
    fn into(self) -> u8 {
        match self {
            Self::Zlib => 0x01,
            Self::Brotli => 0x02,
            Self::Unknown(v) => v,
        }
    }
}

impl TryFrom<u8> for CompressionAlgorithm {
    type Error = TlsError;

    fn try_from(value: u8) -> TlsResult<Self> {
        match value {
            0x01 => Ok(Self::Zlib),
            0x02 => Ok(Self::Brotli),
            _ => {
                warn!("Unknown compression algorithm");
                Ok(Self::Unknown(value))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedCompressionAlgorithm {
    Zlib,
    Brotli,
}

impl SupportedCompressionAlgorithm {
    pub fn to_unsupported(&self) -> CompressionAlgorithm {
        match self {
            Self::Zlib => CompressionAlgorithm::Zlib,
            Self::Brotli => CompressionAlgorithm::Brotli,
        }
    }
}
use crate::error::*;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionMethod {
    Null = 0x00,
    DEFLATE = 0x01,
    LZS = 0x40,
}

impl CompressionMethod {
    pub fn to_supported(&self) -> Option<SupportedCompressionMethod> {
        match self {
            CompressionMethod::Null => Some(SupportedCompressionMethod::Null),
            _ => None,
        }
    }
}

impl TryFrom<u8> for CompressionMethod {
    type Error = TlsError;
    
    fn try_from(value: u8) -> TlsResult<Self> {
        match value {
            0x00 => Ok(Self::Null),
            0x01 => Ok(Self::DEFLATE),
            0x40 => Ok(Self::LZS),
            _ => Err(TlsError::Unknown("compression method"))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedCompressionMethod {
    Null,
}

#[cfg(test)]
mod test_compression_method_parse {
    
}
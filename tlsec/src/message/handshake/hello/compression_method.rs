use crate::error::*;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionMethod {
    Null = 0x00,
    DEFLATE = 0x01,
    LZS = 0x40,
}

impl TryFrom<u8> for CompressionMethod {
    type Error = Error;
    
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Null),
            0x01 => Ok(Self::DEFLATE),
            0x40 => Ok(Self::LZS),
            _ => Err(Error::Unknown("compression method"))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedCompressionMethod {
    Null,
}

impl SupportedCompressionMethod {    
    pub fn compare(&self, method: &CompressionMethod) -> Option<SupportedCompressionMethod> {
        match method {
            CompressionMethod::Null => Some(Self::Null),
            _ => None,
        }
    }
}

#[cfg(test)]
mod test_compression_method_parse {
    
}
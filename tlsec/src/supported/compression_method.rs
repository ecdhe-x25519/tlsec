use crate::messages::handshake::CompressionMethod;

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
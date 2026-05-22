use crate::messages::handshake::extensions::client::CompressionAlgorithm;

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
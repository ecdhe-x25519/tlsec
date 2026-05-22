use crate::messages::handshake::extensions::client::EcPointFormat;

#[derive(Debug, Clone, Copy)]
pub enum SupportedEcPointFormat {
    Uncompressed,
}

impl SupportedEcPointFormat {
    pub fn compare(&self, format: &EcPointFormat) -> Option<SupportedEcPointFormat> {
        match format {
            EcPointFormat::Uncompressed => Some(Self::Uncompressed),
            _ => None,
        }
    }
}
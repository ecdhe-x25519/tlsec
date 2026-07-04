use crate::message::serialize::Serialize;
use crate::message::handshake::certificate::{CertificateEntryExtensionPayload, CertificateEntryExtensionType};

use crate::error::*;

use bytes::*;

use brevno::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCertificateTimestampPayload {
    pub version: SctVersion,
    pub log_id: [u8; 32], // log id
    pub timestamp: u64, // unix epoch, 8 bytes
    pub extensions: Vec<CertificateEntryExtensionPayload>, // length u16
    pub signature: DigitallySigned,
}

impl Serialize for SignedCertificateTimestampPayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.version as u8);
        buf.put_slice(&self.log_id);
        buf.put_u64(self.timestamp);

        let ext_len_pos: usize = buf.len();
        buf.put_u16(0);

        for ext in &self.extensions {
            ext.encode_payload(buf);
        }

        let ext_len: u16 = (buf.len() - ext_len_pos - 2) as u16;
        buf[ext_len_pos..ext_len_pos+2].copy_from_slice(&ext_len.to_be_bytes());

        self.signature.encode(buf);
    }

    fn decode(buf: &mut BytesMut) -> TlsResult<Self> {
        if buf.remaining() < 43 {
            error!(format!("Incomplete data: need {} more bytes", (43 - buf.remaining())));
            return Err(TlsError::Incomplete(43 - buf.remaining()));
        }

        let version: SctVersion = SctVersion::try_from(buf.get_u8())?;

        let mut log_id: [u8; 32] = [0u8; 32];
        buf.copy_to_slice(&mut log_id);

        let timestamp: u64 = buf.get_u64();

        let extensions_length: usize = buf.get_u16() as usize;

        if buf.remaining() < extensions_length + 1 {
            error!(format!("Incomplete data: need {} more bytes", (extensions_length + 1  - buf.remaining())));
            return Err(TlsError::Incomplete(extensions_length + 1  - buf.remaining()));
        }

        let mut exts: BytesMut = buf.split_to(extensions_length);
        let mut extensions: Vec<CertificateEntryExtensionPayload> = Vec::new();
        while exts.remaining() > 0 {
            let ext_type: CertificateEntryExtensionType = CertificateEntryExtensionType::try_from(buf.get_u16())?;
            extensions.push(CertificateEntryExtensionPayload::decode_payload(ext_type, &mut exts)?);
        }

        if buf.remaining() < 1 {
            error!(format!("Incomplete data: need {} more bytes", (1  - buf.remaining())));
            return Err(TlsError::Incomplete(1 - buf.remaining()));
        }

        let signature: DigitallySigned = DigitallySigned::decode(buf)?;

        Ok(Self {
            version,
            log_id,
            timestamp,
            extensions,
            signature,
        })
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SctVersion {
    V1 = 0x00,
}

impl TryFrom<u8> for SctVersion {
    type Error = TlsError;

    fn try_from(value: u8) -> TlsResult<Self> {
        match value {
            0x00 => Ok(Self::V1),
            _ => {
                warn!("Unknown SCT version");
                Err(TlsError::Unknown("SCT version"))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigitallySigned {
    pub hash_algorithm: SctHashAlgorithm,
    pub signature_algorithm: SctSignatureAlgorithm,
    pub signature: Bytes, // length u16
}

impl Serialize for DigitallySigned {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.hash_algorithm.into());
        buf.put_u8(self.signature_algorithm.into());
        buf.put_slice(&self.signature);
    }
    
    fn decode(buf: &mut BytesMut) -> TlsResult<Self> {
        if buf.remaining() < 4 {
            error!(format!("Incomplete data: need {} more bytes", (4 - buf.remaining())));
            return Err(TlsError::Incomplete(4 - buf.remaining()));
        }

        let hash_algorithm: SctHashAlgorithm = SctHashAlgorithm::try_from(buf.get_u8())?;

        let signature_algorithm: SctSignatureAlgorithm = SctSignatureAlgorithm::try_from(buf.get_u8())?;

        let signature_length: usize = buf.get_u16() as usize;

        if buf.remaining() < signature_length {
            error!(format!("Incomplete data: need {} more bytes", (signature_length - buf.remaining())));
            return Err(TlsError::Incomplete(signature_length - buf.remaining()));
        }

        let signature: Bytes = buf.split_to(signature_length).freeze();

        Ok(Self {
            hash_algorithm,
            signature_algorithm,
            signature,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SctHashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
    Unknown(u8)
}

impl Into<u8> for SctHashAlgorithm {
    fn into(self) -> u8 {
        match self {
            Self::Sha256 => 0x04,
            Self::Sha384 => 0x05,
            Self::Sha512 => 0x06,
            Self::Unknown(v) => v,
        }
    }
}

impl TryFrom<u8> for SctHashAlgorithm {
    type Error = TlsError;

    fn try_from(value: u8) -> TlsResult<Self> {
        match value {
            0x04 => Ok(Self::Sha256),
            0x05 => Ok(Self::Sha384),
            0x06 => Ok(Self::Sha512),
            _ => {
                warn!("Unknown SCT hash algorithm");
                Ok(Self::Unknown(value))
            }
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SctSignatureAlgorithm {
    Rsa,
    Ecdsa,
    Unknown(u8),
}

impl Into<u8> for SctSignatureAlgorithm {
    fn into(self) -> u8 {
        match self {
            Self::Rsa => 0x01,
            Self::Ecdsa => 0x03,
            Self::Unknown(v) => v,
        }
    }
}

impl TryFrom<u8> for SctSignatureAlgorithm {
    type Error = TlsError;

    fn try_from(value: u8) -> TlsResult<Self> {
        match value {
            0x01 => Ok(Self::Rsa),
            0x03 => Ok(Self::Ecdsa),
            _ => {
                warn!("Unknown SCT signature algorithm");
                Ok(Self::Unknown(value))
            }
        }
    }
}

#[cfg(test)]
mod test_sct_parse {
    
}
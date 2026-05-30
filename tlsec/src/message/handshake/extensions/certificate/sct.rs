use crate::message::*;
use crate::error::*;

use bytes::*;

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

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 1 {
            return Err(Error::Incomplete(1 - buf.remaining()));
        }

        let version: SctVersion = SctVersion::try_from(buf.get_u8())?;

        if buf.remaining() < 32 {
            return Err(Error::Incomplete(32 - buf.remaining()));
        }

        let mut log_id: [u8; 32] = [0u8; 32];
        buf.copy_to_slice(&mut log_id);

        if buf.remaining() < 8 {
            return Err(Error::Incomplete(8 - buf.remaining()));
        }

        let timestamp: u64 = buf.get_u64();

        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let extensions_length: usize = buf.get_u16() as usize;

        if buf.remaining() < extensions_length {
            return Err(Error::Incomplete(extensions_length - buf.remaining()));
        }

        let mut exts: BytesMut = buf.split_to(extensions_length);
        let mut extensions: Vec<CertificateEntryExtensionPayload> = Vec::new();
        while exts.remaining() > 0 {
            let ext_type: CertificateEntryExtensionType = CertificateEntryExtensionType::try_from(buf.get_u16())?;
            extensions.push(CertificateEntryExtensionPayload::decode_payload(ext_type, &mut exts)?);
        }

        if buf.remaining() < 1 {
            return Err(Error::Incomplete(1 - buf.remaining()));
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
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::V1),
            _ => Err(Error::Unknown("SCT version"))
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
        buf.put_u8(self.hash_algorithm as u8);
        buf.put_u8(self.signature_algorithm as u8);
        buf.put_slice(&self.signature);
    }
    
    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 1 {
            return Err(Error::Incomplete(1 - buf.remaining()));
        }

        let hash_algorithm: SctHashAlgorithm = SctHashAlgorithm::try_from(buf.get_u8())?;

        if buf.remaining() < 1 {
            return Err(Error::Incomplete(1 - buf.remaining()));
        }

        let signature_algorithm: SctSignatureAlgorithm = SctSignatureAlgorithm::try_from(buf.get_u8())?;

        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let signature_length: usize = buf.get_u16() as usize;

        if buf.remaining() < signature_length {
            return Err(Error::Incomplete(signature_length - buf.remaining()));
        }

        let signature: Bytes = buf.split_to(signature_length).freeze();

        Ok(Self {
            hash_algorithm,
            signature_algorithm,
            signature,
        })
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SctHashAlgorithm {
    Sha256 = 0x04,
    Sha384 = 0x05,
    Sha512 = 0x06,
}

impl TryFrom<u8> for SctHashAlgorithm {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x04 => Ok(Self::Sha256),
            0x05 => Ok(Self::Sha384),
            0x06 => Ok(Self::Sha512),
            _ => Err(Error::Unknown("SCT hash algorithm"))
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SctSignatureAlgorithm {
    Rsa = 0x01,
    Ecdsa = 0x03,
}

impl TryFrom<u8> for SctSignatureAlgorithm {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Rsa),
            0x03 => Ok(Self::Ecdsa),
            _ => Err(Error::Unknown("SCT signature algorithm"))
        }
    }
}

#[cfg(test)]
mod test_sct_parse {
    
}
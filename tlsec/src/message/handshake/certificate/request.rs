use crate::message::serialize::Serialize;
use crate::message::handshake::certificate::sig_scheme::SignatureAlgorithmsPayload;
use crate::message::handshake::extensions::certificate::authorities::CertificateAuthoritiesPayload;
use crate::message::handshake::extensions::certificate::oid_filter::OidFiltersPayload;
use crate::message::handshake::extensions::certificate::sig_algo_cert::SignatureAlgorithmsCertPayload;

use crate::error::TlsError;

use bytes::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRequestPayload {
    pub certificate_request_context: Bytes, // length u8
    pub extensions: Vec<CertificateRequestExtension>, // length u16
}

impl Serialize for CertificateRequestPayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.certificate_request_context.len() as u8);
        buf.put_slice(&self.certificate_request_context);

        let ext_len_pos: usize = buf.len();
        buf.put_u16(0);
        
        for ext in &self.extensions {
            ext.encode(buf);
        }
        
        let ext_len: u16 = (buf.len() - ext_len_pos - 2) as u16;
        buf[ext_len_pos..ext_len_pos+2].copy_from_slice(&ext_len.to_be_bytes());
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, TlsError> {
        if buf.remaining() < 1 {
            return Err(TlsError::Incomplete(1 - buf.remaining()));
        }
        
        let ctx_len: usize = buf.get_u8() as usize;
        if buf.remaining() < ctx_len {
            return Err(TlsError::Incomplete(ctx_len - buf.remaining()));
        }
        let certificate_request_context: Bytes = buf.split_to(ctx_len).freeze();

        if buf.remaining() < 2 {
            return Err(TlsError::Incomplete(2 - buf.remaining()));
        }
        
        let ext_len: usize = buf.get_u16() as usize;
        if buf.remaining() < ext_len {
            return Err(TlsError::Incomplete(ext_len - buf.remaining()));
        }
        
        let mut ext_buf: BytesMut = buf.split_to(ext_len);
        let mut extensions: Vec<CertificateRequestExtension> = Vec::new();
        
        while ext_buf.remaining() > 0 {
            let extension_type: CertificateRequestExtensionType = CertificateRequestExtensionType::try_from(ext_buf.get_u16())?;
            let payload: CertificateRequestExtensionPayload = CertificateRequestExtensionPayload::decode_payload(extension_type, &mut ext_buf)?;
            let ext: CertificateRequestExtension = CertificateRequestExtension {
                extension_type,
                payload,
            };

            extensions.push(ext);
        }

        Ok(CertificateRequestPayload {
            certificate_request_context,
            extensions,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRequestExtension {
    pub extension_type: CertificateRequestExtensionType,
    pub payload: CertificateRequestExtensionPayload,
}

impl Serialize for CertificateRequestExtension {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.extension_type as u16);

        let len_pos: usize = buf.len();
        buf.put_u16(0);

        self.payload.encode_payload(buf);

        let len: u16 = (buf.len() - len_pos - 2) as u16;
        buf[len_pos..len_pos+2].copy_from_slice(&len.to_be_bytes())
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, TlsError> {
        let extension_type: CertificateRequestExtensionType = CertificateRequestExtensionType::try_from(buf.get_u16())?;
        let length: usize = buf.get_u16() as usize;

        if buf.remaining() < length {
            return Err(TlsError::Incomplete(length - buf.remaining()));
        }

        let mut data_buf: BytesMut = buf.split_to(length);
        let payload: CertificateRequestExtensionPayload = CertificateRequestExtensionPayload::decode_payload(extension_type, &mut data_buf)?;

        Ok(Self {
            extension_type,
            payload,
        })
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateRequestExtensionType {
    SignatureAlgorithms = 0x000D,
    CertificateAuthorities = 0x002F,
    OidFilters = 0x0030,
    SignatureAlgorithmsCert = 0x0032,
}

impl TryFrom<u16> for CertificateRequestExtensionType {
    type Error = TlsError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x000D => Ok(Self::SignatureAlgorithms),
            0x002F => Ok(Self::CertificateAuthorities),
            0x0030 => Ok(Self::OidFilters),
            0x0032 => Ok(Self::SignatureAlgorithmsCert),
            _ => Err(TlsError::Unknown("certificate request extension")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateRequestExtensionPayload {
    SignatureAlgorithms(SignatureAlgorithmsPayload),
    CertificateAuthorities(CertificateAuthoritiesPayload),
    OidFilters(OidFiltersPayload),
    SignatureAlgorithmsCert(SignatureAlgorithmsCertPayload),
}

impl CertificateRequestExtensionPayload {
    pub fn encode_payload(&self, buf: &mut BytesMut) {
        match self {
            Self::SignatureAlgorithms(p) => p.encode(buf),
            Self::CertificateAuthorities(p) => p.encode(buf),
            Self::OidFilters(p) => p.encode(buf),
            Self::SignatureAlgorithmsCert(p) => p.encode(buf),
        }
    }

    pub fn decode_payload(extension_type: CertificateRequestExtensionType, buf: &mut BytesMut) -> Result<Self, TlsError> {
        match extension_type {
            CertificateRequestExtensionType::SignatureAlgorithms => Ok(Self::SignatureAlgorithms(SignatureAlgorithmsPayload::decode(buf)?)),
            CertificateRequestExtensionType::CertificateAuthorities => Ok(Self::CertificateAuthorities(CertificateAuthoritiesPayload::decode(buf)?)),
            CertificateRequestExtensionType::OidFilters => Ok(Self::OidFilters(OidFiltersPayload::decode(buf)?)),
            CertificateRequestExtensionType::SignatureAlgorithmsCert => Ok(Self::SignatureAlgorithmsCert(SignatureAlgorithmsCertPayload::decode(buf)?)),
        }
    }
}

#[cfg(test)]
mod test_cert_request_parse {
    
}
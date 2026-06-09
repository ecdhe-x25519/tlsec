use crate::message::handshake::extensions::certificate::sct::SignedCertificateTimestampPayload;
use crate::message::handshake::extensions::certificate::status_request::StatusRequestPayload;
use crate::message::serialize::Serialize;

use crate::error::TlsError;

use bytes::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificatePayload {
    pub certificate_request_context: Bytes, // length u8
    pub certificate_list: Vec<CertificateEntryPayload>, // length 3 bytes
}

impl Serialize for CertificatePayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.certificate_request_context.len() as u8);

        buf.put_slice(&self.certificate_request_context);

        let list_len_pos: usize = buf.len();
        buf.put_slice(&[0u8; 3]);
        
        for cert in &self.certificate_list {
            cert.encode(buf);
        }

        let list_len: u32 = (buf.len() - list_len_pos - 3) as u32;
        let len_bytes: [u8; _] = list_len.to_be_bytes();
        buf[list_len_pos..list_len_pos+3].copy_from_slice(&len_bytes[1..]);
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, TlsError> {
        if buf.remaining() < 1 {
            return Err(TlsError::Incomplete(1 - buf.remaining()));
        }

        let certificate_request_context_length: usize = buf.get_u8() as usize;

        if buf.remaining() < certificate_request_context_length {
            return Err(TlsError::Incomplete(certificate_request_context_length - buf.remaining()));
        }

        let certificate_request_context: Bytes = buf.split_to(certificate_request_context_length).freeze();

        if buf.remaining() < 3 {
            return Err(TlsError::Incomplete(3 - buf.remaining()));
        }

        let len_bytes: [u8; 3] = [buf.get_u8(), buf.get_u8(), buf.get_u8()];
        let certificate_list_length: usize = u32::from_be_bytes([0, len_bytes[0], len_bytes[1], len_bytes[2]]) as usize;

        if buf.remaining() < certificate_list_length {
            return Err(TlsError::Incomplete(certificate_list_length - buf.remaining()));
        }

        let mut list_buf: BytesMut = buf.split_to(certificate_list_length);
        let mut certificate_list: Vec<CertificateEntryPayload> = Vec::new();
        while list_buf.remaining() > 0 {
            let cert: CertificateEntryPayload = CertificateEntryPayload::decode(&mut list_buf)?;
            certificate_list.push(cert);
        }

        Ok(Self {
            certificate_request_context,
            certificate_list,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateEntryPayload {
    pub certificate_data: Bytes, // length = 3 bytes
    pub extensions: Vec<CertificateEntryExtension>, // length = u16
}

impl Serialize for CertificateEntryPayload {
    fn encode(&self, buf: &mut BytesMut) {
        let cert_len_pos: usize = buf.len();
        buf.put_slice(&[0u8; 3]);

        let cert_len: u32 = self.certificate_data.len() as u32;
        let len_bytes: [u8; _] = cert_len.to_be_bytes();
        buf[cert_len_pos..cert_len_pos+3].copy_from_slice(&len_bytes[1..]);
        
        buf.put_slice(&self.certificate_data);
        
        let ext_len_pos: usize = buf.len();
        buf.put_u16(0);
        for ext in &self.extensions {
            ext.encode(buf);
        }
        
        let ext_len: u16 = (buf.len() - ext_len_pos - 2) as u16;
        buf[ext_len_pos..ext_len_pos+2].copy_from_slice(&ext_len.to_be_bytes());
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, TlsError> {
        if buf.remaining() < 3 {
            return Err(TlsError::Incomplete(3 - buf.remaining()));
        }

        let len_bytes: [u8; 3] = [buf.get_u8(), buf.get_u8(), buf.get_u8()];
        let cert_length: usize = u32::from_be_bytes([0, len_bytes[0], len_bytes[1], len_bytes[2]]) as usize;

        if buf.remaining() < cert_length {
            return Err(TlsError::Incomplete(cert_length - buf.remaining()));
        }

        let certificate_data: Bytes = buf.split_to(cert_length).freeze();

        if buf.remaining() < 2 {
            return Err(TlsError::Incomplete(2 - buf.remaining()));
        }

        let ext_length: usize = buf.get_u16() as usize;

        if buf.remaining() < ext_length {
            return Err(TlsError::Incomplete(ext_length - buf.remaining()));
        }

        let mut ext_buf: BytesMut = buf.split_to(ext_length);
        let mut extensions: Vec<CertificateEntryExtension> = Vec::new();
        while ext_buf.remaining() > 0 {
            let extension_type: CertificateEntryExtensionType = CertificateEntryExtensionType::try_from(ext_buf.get_u16())?;
            let payload: CertificateEntryExtensionPayload = CertificateEntryExtensionPayload::decode_payload(extension_type, &mut ext_buf)?;
            let ext: CertificateEntryExtension = CertificateEntryExtension { extension_type, payload };
            extensions.push(ext);
        }

        Ok(Self {
            certificate_data,
            extensions,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateEntryExtension {
    pub extension_type: CertificateEntryExtensionType,
    pub payload: CertificateEntryExtensionPayload, // length u16
}

impl Serialize for CertificateEntryExtension {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.extension_type as u16);
        self.payload.encode_payload(buf);
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, TlsError> {
        if buf.remaining() < 2 {
            return Err(TlsError::Incomplete(2 - buf.remaining()));
        }

        let extension_type: CertificateEntryExtensionType = CertificateEntryExtensionType::try_from(buf.get_u16())?;

        if buf.remaining() < 2 {
            return Err(TlsError::Incomplete(2 - buf.remaining()));
        }

        let length: usize = buf.get_u16() as usize;

        if buf.remaining() < length {
            return Err(TlsError::Incomplete(length - buf.remaining()));
        }

        let payload: CertificateEntryExtensionPayload = CertificateEntryExtensionPayload::decode_payload(extension_type, buf)?;

        Ok(Self {
            extension_type,
            payload,
        })
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateEntryExtensionType {
    StatusRequest = 0x0005,
    SignedCertificateTimestamp = 0x0012,
}

impl TryFrom<u16> for CertificateEntryExtensionType {
    type Error = TlsError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0005 => Ok(Self::StatusRequest),
            0x0012 => Ok(Self::SignedCertificateTimestamp),
            _ => Err(TlsError::Unknown("certificate extension")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateEntryExtensionPayload {
    StatusRequest(StatusRequestPayload),
    SignedCertificateTimestamp(SignedCertificateTimestampPayload),
}

impl CertificateEntryExtensionPayload {
    pub fn encode_payload(&self, buf: &mut BytesMut) {
        match self {
            Self::StatusRequest(p) => p.encode(buf),
            Self::SignedCertificateTimestamp(p) => p.encode(buf),
        }
    }

    pub fn decode_payload(extension_type: CertificateEntryExtensionType, buf: &mut BytesMut) -> Result<Self, TlsError> {
        match extension_type {
            CertificateEntryExtensionType::StatusRequest => Ok(Self::StatusRequest(StatusRequestPayload::decode(buf)?)),
            CertificateEntryExtensionType::SignedCertificateTimestamp => Ok(Self::SignedCertificateTimestamp(SignedCertificateTimestampPayload::decode(buf)?)),
        }
    }
}

#[cfg(test)]
mod test_cert_parse {
    use crate::message::handshake::extensions::certificate::status_request::StatusType;

    use super::*;

    #[test]
    fn cert_parse() {
        let mut buf: BytesMut = BytesMut::new();

        let zero: Bytes = Bytes::new();

        let sr_payload: StatusRequestPayload = StatusRequestPayload {
            status_type: StatusType::Ocsp,
            responder_id_list: zero.clone(),
            request_extensions: zero.clone(),
        };

        let ext_payload: CertificateEntryExtensionPayload = CertificateEntryExtensionPayload::StatusRequest(sr_payload);

        let ext: CertificateEntryExtension = CertificateEntryExtension {
            extension_type: CertificateEntryExtensionType::StatusRequest,
            payload: ext_payload,
        };

        let cert_list: CertificateEntryPayload = CertificateEntryPayload {
            certificate_data: zero.clone(),
            extensions: vec![ext],
        };

        let cert: CertificatePayload = CertificatePayload {
            certificate_request_context: zero,
            certificate_list: vec![cert_list],
        };

        cert.encode(&mut buf);

        let decoded: CertificatePayload = CertificatePayload::decode(&mut buf).unwrap();

        assert_eq!(cert, decoded);
    }
}
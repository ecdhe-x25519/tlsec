use crate::message::{alert::AlertDescription, handshake::extensions::*};
use crate::message::handshake::encrypted_extensions::EncryptedExtensionsPayload;
use crate::message::handshake::hello::*;
use crate::message::serialize::Serialize;
use crate::message::handshake::certificate::*;

use crate::error::*;

use brevno::{error, warn};

use bytes::*;

#[derive(Debug, PartialEq, Eq)]
pub struct HandshakeMessage {
    pub handshake_type: HandshakeType,
    pub payload: HandshakePayload, // length = 3 bytes
    pub raw: Option<BytesMut>,
}

impl HandshakeMessage {
    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.handshake_type as u8);

        let len_pos: usize = buf.len();
        buf.put_bytes(0, 3);

        self.payload.encode_payload(buf);

        let len: usize = buf.len() - len_pos - 3;
        buf[len_pos..len_pos+3].copy_from_slice(&len.to_be_bytes());
    }

    pub(crate) fn decode(buf: &mut BytesMut, cipher_suite: Option<&SupportedCipherSuite>) -> TlsResult<Self> {
        if buf.remaining() < 5 {
            error!(format!("Incomplete data: need {} more bytes", (2 - buf.remaining())));
            return Err(TlsError::Incomplete(5 - buf.remaining()));
        }

        let start_len: usize = buf.len();

        let handshake_type: HandshakeType = HandshakeType::try_from(buf.get_u8())?;
        let length: [u8; 3] = [buf.get_u8(), buf.get_u8(), buf.get_u8()];

        let len: usize = u32::from_be_bytes([0, length[0], length[1], length[2]]) as usize;
        
        if buf.remaining() < len {
            error!(format!("Incomplete data: need {} more bytes", (2 - buf.remaining())));
            return Err(TlsError::Incomplete(len - buf.remaining()));
        }

        let raw = Some(buf.clone().split_to(start_len - len));

        let mut payload_buf: BytesMut = buf.split_to(len);
        let payload: HandshakePayload = HandshakePayload::decode_payload(handshake_type, &mut payload_buf, cipher_suite)?;

        Ok(Self {
            handshake_type,
            payload,
            raw,
        })
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeType {
    ClientHello = 0x01,
    EndOfEarlyData = 0x05,
    ServerHello = 0x02,
    NewSessionTicket = 0x04,
    EncryptedExtensions = 0x08,
    CertificateRequest = 0x0D,
    Certificate = 0x0B,
    CompressedCertificate = 0x19,
    CertificateVerify = 0x0F,
    Finished = 0x14,
    KeyUpdate = 0x18,
}

impl TryFrom<u8> for HandshakeType {
    type Error = TlsError;
    
    fn try_from(value: u8) -> TlsResult<Self> {
        match value {
            0x01 => Ok(Self::ClientHello),
            0x02 => Ok(Self::ServerHello),
            0x05 => Ok(Self::EndOfEarlyData),
            0x04 => Ok(Self::NewSessionTicket),
            0x08 => Ok(Self::EncryptedExtensions),
            0x0D => Ok(Self::CertificateRequest),
            0x0B => Ok(Self::Certificate),
            0x19 => Ok(Self::CompressedCertificate),
            0x0F => Ok(Self::CertificateVerify),
            0x14 => Ok(Self::Finished),
            0x18 => Ok(Self::KeyUpdate),
            _ => {
                error!(format!("Unknown handshake type: {}", value));
                Err(TlsError::Unknown("handshake type"))
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum HandshakePayload {
    ClientHello(ClientHelloPayload),
    ServerHello(ServerHelloPayload),
    EncryptedExtensions(EncryptedExtensionsPayload),
    CertificateRequest(CertificateRequestPayload),
    Certificate(CertificatePayload),
    CompressedCertificate(CompressedCertificatePayload),
    CertificateVerify(CertificateVerifyPayload),
    Finished(FinishedPayload),
    KeyUpdate(KeyUpdatePayload),
    NewSessionTicket(NewSessionTicketPayload),
    EndOfEarlyData,
}

impl HandshakePayload {
    pub(crate) fn encode_payload(&self, buf: &mut BytesMut) {
        match self {
            Self::ClientHello(p) => p.encode(buf),
            Self::ServerHello(p) => p.encode(buf),
            Self::EncryptedExtensions(p) => p.encode(buf),
            Self::CertificateRequest(p) => p.encode(buf),
            Self::Certificate(p) => p.encode(buf),
            Self::CompressedCertificate(p) => p.encode(buf),
            Self::CertificateVerify(p) => p.encode(buf),
            Self::Finished(p) => p.encode(buf),
            Self::KeyUpdate(p) => p.encode(buf),
            Self::NewSessionTicket(p) => p.encode(buf),
            Self::EndOfEarlyData => {},
        }
    }

    pub(crate) fn decode_payload(handshake_type: HandshakeType, buf: &mut BytesMut, cipher_suite: Option<&SupportedCipherSuite>) -> TlsResult<Self> {
        match handshake_type {
            HandshakeType::ClientHello => Ok(Self::ClientHello(ClientHelloPayload::decode(buf)?)),
            HandshakeType::ServerHello => Ok(Self::ServerHello(ServerHelloPayload::decode(buf)?)),
            HandshakeType::EncryptedExtensions => Ok(Self::EncryptedExtensions(EncryptedExtensionsPayload::decode(buf)?)),
            HandshakeType::CertificateRequest => Ok(Self::CertificateRequest(CertificateRequestPayload::decode(buf)?)),
            HandshakeType::Certificate => Ok(Self::Certificate(CertificatePayload::decode(buf)?)),
            HandshakeType::CompressedCertificate => Ok(Self::CompressedCertificate(CompressedCertificatePayload::decode(buf)?)),
            HandshakeType::CertificateVerify => Ok(Self::CertificateVerify(CertificateVerifyPayload::decode(buf)?)),
            HandshakeType::Finished => Ok(Self::Finished(FinishedPayload::decode(buf, cipher_suite)?)),
            HandshakeType::KeyUpdate => Ok(Self::KeyUpdate(KeyUpdatePayload::decode(buf)?)),
            HandshakeType::NewSessionTicket => Ok(Self::NewSessionTicket(NewSessionTicketPayload::decode(buf)?)),
            HandshakeType::EndOfEarlyData => Ok(Self::EndOfEarlyData),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct NewSessionTicketPayload {
    pub ticket_lifetime: u32,
    pub ticket_age_add: u32,
    pub ticket_nonce: Vec<u8>, // 1 byte len
    pub ticket: Vec<u8>, // 2 bytes len
    pub extensions: Vec<Extension>, // 2 bytes len
}

impl Serialize for NewSessionTicketPayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.ticket_lifetime);
        buf.put_u32(self.ticket_age_add);
        buf.put_u8(self.ticket_nonce.len() as u8);
        buf.put_slice(&self.ticket_nonce);
        buf.put_u16(self.ticket.len() as u16);
        buf.put_slice(&self.ticket);
        
        let ext_len_pos = buf.len();
        buf.put_u16(0);
        for ext in &self.extensions {
            ext.encode(buf);
        }
        let ext_len = (buf.len() - ext_len_pos - 2) as u16;
        buf[ext_len_pos..ext_len_pos+2].copy_from_slice(&ext_len.to_be_bytes());
    }

    fn decode(buf: &mut BytesMut) -> TlsResult<Self> {
        if buf.remaining() < 9 {
            return Err(TlsError::Incomplete(4 - buf.remaining()));
        }

        let ticket_lifetime = buf.get_u32();

        let ticket_age_add = buf.get_u32();
        
        let nonce_len = buf.get_u8() as usize;

        if buf.remaining() < nonce_len {
            return Err(TlsError::Incomplete(nonce_len - buf.remaining()));
        }

        let ticket_nonce = buf.split_to(nonce_len).to_vec();
        
        if buf.remaining() < 2 {
            return Err(TlsError::Incomplete(2 - buf.remaining()));
        }

        let ticket_len = buf.get_u16() as usize;
        if buf.remaining() < ticket_len {
            return Err(TlsError::Incomplete(ticket_len - buf.remaining()));
        }

        let ticket = buf.split_to(ticket_len).to_vec();
        
        if buf.remaining() < 2 {
            return Err(TlsError::Incomplete(2 - buf.remaining()));
        }

        let ext_len = buf.get_u16() as usize;

        if buf.remaining() < ext_len {
            return Err(TlsError::Incomplete(ext_len - buf.remaining()));
        }

        let mut ext_buf = buf.split_to(ext_len);

        let mut extensions = Vec::new();
        
        while ext_buf.remaining() > 0 {
            extensions.push(Extension::decode(&mut ext_buf)?);
        }
        
        Ok(NewSessionTicketPayload {
            ticket_lifetime,
            ticket_age_add,
            ticket_nonce,
            ticket,
            extensions,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct FinishedPayload {
    pub verify_data: Bytes,
}

impl FinishedPayload {
    pub(crate) fn encode(&self, buf: &mut BytesMut) {
        buf.put_slice(&self.verify_data);
    }

    pub(crate) fn decode(buf: &mut BytesMut, cipher_suite: Option<&SupportedCipherSuite>) -> TlsResult<Self> {
        let cipher_suite: usize = match cipher_suite {
            Some(cs) => cs.hash_len(),
            None => return Err(TlsError::Crypto(format!("cipher suite not set"))),
        };

        if buf.remaining() < cipher_suite {
            error!(format!("Incomplete data: need {} more bytes", (cipher_suite - buf.remaining())));
            return Err(TlsError::Incomplete(cipher_suite - buf.remaining()));
        }
        
        let verify_data: Bytes = buf.split_to(cipher_suite).freeze();
        
        Ok(FinishedPayload { verify_data })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct KeyUpdatePayload {
    pub request_update: KeyUpdateRequest,
}

impl Serialize for KeyUpdatePayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.request_update as u8);
    }

    fn decode(buf: &mut BytesMut) -> TlsResult<Self> {
        let request_update: KeyUpdateRequest = KeyUpdateRequest::try_from(buf.get_u8())?;
        Ok(Self {
            request_update,
        })
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUpdateRequest {
    UpdateNotRequested = 0x00,
    UpdateRequested = 0x01,
}

impl TryFrom<u8> for KeyUpdateRequest {
    type Error = TlsError;

    fn try_from(value: u8) -> TlsResult<Self> {
        match value {
            0x00 => Ok(KeyUpdateRequest::UpdateNotRequested),
            0x01 => Ok(KeyUpdateRequest::UpdateRequested),
            _ => {
                warn!("Unknown key update request");
                Err(TlsError::Alert(AlertDescription::MissingExtension))
            }
        }
    }
}

#[cfg(test)]
mod test_handshake_message_parse {
    
}
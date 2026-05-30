use crate::message::*;
use crate::error::*;

use bytes::*;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerHandshakeType {
    ServerHello = 0x02,
    NewSessionTicket = 0x04,
    EncryptedExtensions = 0x08,
    Certificate = 0x0B,
    CertificateVerify = 0x0F,
    CertificateRequest = 0x0D,
    HelloRetryRequest,
}

impl TryFrom<u8> for ServerHandshakeType {
    type Error = Error;
    
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x02 => Ok(ServerHandshakeType::ServerHello),
            0x04 => Ok(ServerHandshakeType::NewSessionTicket),
            0x08 => Ok(ServerHandshakeType::EncryptedExtensions),
            0x0B => Ok(ServerHandshakeType::Certificate),
            0x0D => Ok(ServerHandshakeType::CertificateRequest),
            0x0F => Ok(ServerHandshakeType::CertificateVerify),
            _ => Err(Error::Unknown("handshake type")),
        }
    }
}

pub enum ServerHandshakePayload {
    ServerHello(ServerHelloPayload),
    EncryptedExtensions(EncryptedExtensionsPayload),
    Certificate(CertificatePayload),
    CertificateVerify(CertificateVerifyPayload),
}

impl ServerHandshakePayload {
    pub fn encode_payload(&self, buf: &mut BytesMut) {
        match self {
            Self::ServerHello(p) => p.encode(buf),
            Self::EncryptedExtensions(p) => p.encode(buf),
            Self::Certificate(p) => p.encode(buf),
            Self::CertificateVerify(p) => p.encode(buf),
        }
    }

    pub fn decode_payload(handshake_type: ServerHandshakeType, buf: &mut BytesMut) -> Result<Self, Error> {
        match handshake_type {
            ServerHandshakeType::ServerHello => Ok(Self::ServerHello(ServerHelloPayload::decode(buf)?)),
            ServerHandshakeType::EncryptedExtensions => Ok(Self::EncryptedExtensions(EncryptedExtensionsPayload::decode(buf)?)),
            ServerHandshakeType::Certificate => Ok(Self::Certificate(CertificatePayload::decode(buf)?)),
            ServerHandshakeType::CertificateVerify => Ok(Self::CertificateVerify(CertificateVerifyPayload::decode(buf)?)),
            _ => Err(Error::Unknown("handshake type")),
        }
    }
}

#[cfg(test)]
mod test_server_msg_parse {
    
}
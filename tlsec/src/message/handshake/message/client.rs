use crate::message::serialize::Serialize;
use crate::message::handshake::certificate::certificate::CertificatePayload;
use crate::message::handshake::certificate::certificate_verify::CertificateVerifyPayload;
use crate::message::handshake::hello::client::ClientHelloPayload;

use crate::error::Error;

use bytes::*;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientHandshakeType {
    ClientHello = 0x01,
    EndOfEarlyData = 0x05,
    Certificate = 0x0B,
    CertificateVerify = 0x0F,
}

impl TryFrom<u8> for ClientHandshakeType {
    type Error = Error;
    
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(ClientHandshakeType::ClientHello),
            0x05 => Ok(ClientHandshakeType::EndOfEarlyData),
            0x0B => Ok(ClientHandshakeType::Certificate),
            0x0F => Ok(ClientHandshakeType::CertificateVerify),
            _ => Err(Error::Unknown("handshake type")),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ClientHandshakePayload {
    ClientHello(ClientHelloPayload),
    EndOfEarlyData,
    Certificate(CertificatePayload),
    CertificateVerify(CertificateVerifyPayload),
}

impl ClientHandshakePayload {
    pub fn encode_payload(&self, buf: &mut BytesMut) {
        match self {
            Self::ClientHello(p) => p.encode(buf),
            Self::EndOfEarlyData => (),
            Self::Certificate(p) => p.encode(buf),
            Self::CertificateVerify(p) => p.encode(buf),
        }
    }

    pub fn decode_payload(handshake_type: ClientHandshakeType, buf: &mut BytesMut) -> Result<Self, Error> {
        match handshake_type {
            ClientHandshakeType::ClientHello => Ok(Self::ClientHello(ClientHelloPayload::decode(buf)?)),
            ClientHandshakeType::EndOfEarlyData => Ok(Self::EndOfEarlyData),
            ClientHandshakeType::Certificate => Ok(Self::Certificate(CertificatePayload::decode(buf)?)),
            ClientHandshakeType::CertificateVerify => Ok(Self::CertificateVerify(CertificateVerifyPayload::decode(buf)?)),
        }
    }
}

#[cfg(test)]
mod test_client_msg_parse {
    
}
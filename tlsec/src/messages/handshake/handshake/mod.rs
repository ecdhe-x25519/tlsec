pub mod client;
pub mod server;
pub mod certificate;

use crate::encryption::cipher_suite::SupportedCipherSuite;

use super::*;
use super::super::*;

use client::*;
use server::*;

pub struct HandshakeMessage {
    pub handshake_type: HandshakeType,
    pub payload: HandshakePayload, // length = 3 bytes
}

impl Serialize for HandshakeMessage {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.handshake_type.into());

        let len_pos: usize = buf.len();
        buf.put_bytes(0, 3);

        self.payload.encode_payload(buf);

        let len: usize = buf.len() - len_pos - 3;
        buf[len_pos..len_pos+3].copy_from_slice(&len.to_be_bytes());
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 5 {
            return Err(Error::Incomplete(5 - buf.remaining()));
        }

        let handshake_type: HandshakeType = HandshakeType::try_from(buf.get_u8())?;
        let length: [u8; 3] = [buf.get_u8(), buf.get_u8(), buf.get_u8()];

        let len: usize = u32::from_be_bytes([0, length[0], length[1], length[2]]) as usize;
        
        if buf.remaining() < len {
            return Err(Error::Incomplete(len - buf.remaining()));
        }

        let mut payload_buf: BytesMut = buf.split_to(len);
        let payload: HandshakePayload = HandshakePayload::decode_payload(handshake_type, &mut payload_buf)?;

        Ok(Self {
            handshake_type,
            payload,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeType {
    Client(ClientHandshakeType),
    Server(ServerHandshakeType),
}

impl Into<u8> for HandshakeType {
    fn into(self) -> u8 {
        match self {
            Self::Client(typ) => typ as u8,
            Self::Server(typ) => typ as u8,
        }
    }
}

impl TryFrom<u8> for HandshakeType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if let Ok(typ) = ServerHandshakeType::try_from(value) {
            return Ok(HandshakeType::Server(typ));
        }

        if let Ok(typ) = ClientHandshakeType::try_from(value) {
            return Ok(HandshakeType::Client(typ));
        }
        
        Err(Error::UnexpectedMessage)
    }
}

pub enum HandshakePayload {
    Client(ClientHandshakePayload),
    Server(ServerHandshakePayload),
}

impl HandshakePayload {
    pub fn encode_payload(&self, buf: &mut BytesMut) {
        match self {
            Self::Client(typ) => typ.encode_payload(buf),
            Self::Server(typ) => typ.encode_payload(buf),
        }
    }

    pub fn decode_payload(extension_type: HandshakeType, buf: &mut BytesMut) -> Result<Self, Error> {
        match extension_type {
            HandshakeType::Client(z) => Ok(Self::Client(ClientHandshakePayload::decode_payload(z, buf)?)),
            HandshakeType::Server(z) => Ok(Self::Server(ServerHandshakePayload::decode_payload(z, buf)?)),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommonHandshakeType {
    Finished = 0x14,
    KeyUpdate = 0x18,
}

impl TryFrom<u8> for CommonHandshakeType {
    type Error = Error;
    
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x14 => Ok(Self::Finished),
            0x18 => Ok(Self::KeyUpdate),
            _ => Err(Error::UnsupportedHandshakeType),
        }
    }
}

pub enum CommonHandshakePayload {
    Finished(FinishedPayload),
    KeyUpdate(KeyUpdatePayload),
}

impl CommonHandshakePayload {
    pub fn encode_payload(&self, buf: &mut BytesMut) {
        match self {
            Self::Finished(p) => p.encode(buf),
            Self::KeyUpdate(p) => p.encode(buf),
        }
    }

    pub fn decode_payload(handshake_type: CommonHandshakeType, buf: &mut BytesMut, cipher_suite: SupportedCipherSuite) -> Result<Self, Error> {
        match handshake_type {
            CommonHandshakeType::Finished => Ok(CommonHandshakePayload::Finished(FinishedPayload::decode(buf, cipher_suite)?)),
            CommonHandshakeType::KeyUpdate => Ok(CommonHandshakePayload::KeyUpdate(KeyUpdatePayload::decode(buf)?)),
        }
    }
}

pub struct FinishedPayload {
    pub verify_data: BytesMut,
}

impl FinishedPayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_slice(&self.verify_data);
    }

    fn decode(buf: &mut BytesMut, cipher_suite: SupportedCipherSuite) -> Result<Self, Error> {
        let cipher_suite: usize = match cipher_suite {
            SupportedCipherSuite::Aes128 => SupportedCipherSuite::Aes128.hash_len(),
            SupportedCipherSuite::Aes256 => SupportedCipherSuite::Aes256.hash_len(),
            SupportedCipherSuite::ChaCha20 => SupportedCipherSuite::ChaCha20.hash_len(),
        };

        if buf.remaining() < cipher_suite {
            return Err(Error::Incomplete(cipher_suite - buf.remaining()));
        }
        
        let verify_data: BytesMut = buf.split_to(cipher_suite);
        
        Ok(FinishedPayload { verify_data })
    }
}

pub struct KeyUpdatePayload {
    pub request_update: KeyUpdateRequest,
}

impl Serialize for KeyUpdatePayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.request_update as u8);
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        let request_update: KeyUpdateRequest = KeyUpdateRequest::try_from(buf.get_u8())?;
        Ok(Self {
            request_update,
        })
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum KeyUpdateRequest {
    UpdateNotRequested = 0x00,
    UpdateRequested = 0x01,
}

impl TryFrom<u8> for KeyUpdateRequest {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(KeyUpdateRequest::UpdateNotRequested),
            1 => Ok(KeyUpdateRequest::UpdateRequested),
            _ => Err(Error::Handshake("unknown key update"))
        }
    }
}
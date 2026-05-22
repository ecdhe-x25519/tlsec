use super::*;
use super::extensions::*;

use certificate::*;

const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

pub fn is_hello_retry_request(hello_random: BytesMut) -> bool {
    let hrr: BytesMut = BytesMut::from_iter(HRR_RANDOM);
    if hello_random == hrr {
        true
    } else {
        false
    }
}

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
            _ => Err(Error::UnsupportedHandshakeType),
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
            _ => Err(Error::UnsupportedHandshakeType),
        }
    }
}

pub struct ServerHelloPayload {
    pub legacy_version: Version,
    pub random: [u8; 32],
    pub legacy_session_id_echo: Vec<u8>, // length = u8
    pub cipher_suite: CipherSuite,
    pub legacy_compression_method: CompressionMethod,
    pub extensions: Vec<Extension>, // length = u16
}

impl Serialize for ServerHelloPayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.legacy_version as u16);
        buf.put_slice(&self.random);
        buf.put_u8(self.legacy_session_id_echo.len() as u8);
        buf.put_slice(&self.legacy_session_id_echo);
        buf.put_u16(self.cipher_suite as u16);
        buf.put_u8(self.legacy_compression_method as u8);
        
        let ext_len_pos: usize = buf.len();
        buf.put_u16(0);
        
        for ext in &self.extensions {
            ext.encode(buf);
        }
        
        let ext_len: u16 = (buf.len() - ext_len_pos - 2) as u16;
        buf[ext_len_pos..ext_len_pos+2].copy_from_slice(&ext_len.to_be_bytes());
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let legacy_version: Version = Version::try_from(buf.get_u16())?;

        if buf.remaining() < 32 {
            return Err(Error::Incomplete(32 - buf.remaining()));
        }

        let mut random_bytes: [u8; 32] = [0u8; 32];
        buf.copy_to_slice(&mut random_bytes);
        let random: [u8; 32] = random_bytes;

        if buf.remaining() < 1 {
            return Err(Error::Incomplete(1 - buf.remaining()));
        }

        let legacy_session_id_echo_length: usize = buf.get_u8() as usize;

        if legacy_session_id_echo_length > 32 {
            return Err(Error::Handshake("invalid session id length"));
        }
        if buf.remaining() < legacy_session_id_echo_length {
            return Err(Error::Incomplete(legacy_session_id_echo_length - buf.remaining()));
        }

        let mut legacy_session_id_echo: Vec<u8> = vec![0u8; legacy_session_id_echo_length];
        buf.copy_to_slice(&mut legacy_session_id_echo);

        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }
        let cipher_suite: CipherSuite = CipherSuite::try_from(buf.get_u16())?;

        if buf.remaining() < 1 {
            return Err(Error::Incomplete(1 - buf.remaining()));
        }
        let legacy_compression_method: CompressionMethod = CompressionMethod::try_from(buf.get_u8())?;

        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }
        let extensions_length: usize = buf.get_u16() as usize;
        if buf.remaining() < extensions_length {
            return Err(Error::Incomplete(extensions_length - buf.remaining()));
        }

        let mut exts: BytesMut = buf.split_to(extensions_length);
        let mut extensions: Vec<Extension> = Vec::new();
        while exts.remaining() > 0 {
            extensions.push(Extension::decode(&mut exts)?);
        }

        Ok(Self {
            legacy_version,
            random,
            legacy_session_id_echo,
            cipher_suite,
            legacy_compression_method,
            extensions,
        })
    }
}

pub struct EncryptedExtensionsPayload {
    pub extensions: Vec<Extension>, // length = u16
}

impl Serialize for EncryptedExtensionsPayload {
    fn encode(&self, buf: &mut BytesMut) {
        let len_pos: usize = buf.len();
        buf.put_u16(0);

        for ext in &self.extensions {
            ext.encode(buf);
        }
        
        let len: u16 = (buf.len() - len_pos - 2) as u16;
        buf[len_pos..len_pos+2].copy_from_slice(&len.to_be_bytes());
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let length: usize = buf.get_u16() as usize;

        if buf.remaining() < length {
            return Err(Error::Incomplete(length - buf.remaining()));
        }

        let mut ext_buf: BytesMut = buf.split_to(length);
        let mut extensions: Vec<Extension> = Vec::new();
        while ext_buf.remaining() > 0 {
            extensions.push(Extension::decode(&mut ext_buf)?);
        }

        Ok(Self {
            extensions,
        })
    }
}
use crate::message::serialize::Serialize;
use crate::message::handshake::extensions::alpn::AlpnPayload;
use crate::message::handshake::extensions::server::key_share::KeyShareHelloRetryRequest;
use crate::message::handshake::extensions::server::key_share::KeyShareServer;
use crate::message::handshake::extensions::server::supported_versions::SupportedVersionsServer;

use crate::error::Error;

use bytes::*;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerExtensionType {
    KeyShare = 0x0033,
    SupportedVersions = 0x002B,
    RenegotiationInfo = 0xFF01,
    ALPN = 0x0010,
}

impl TryFrom<u16> for ServerExtensionType {
    type Error = Error;
    
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0033 => Ok(Self::KeyShare),
            0x002B => Ok(Self::SupportedVersions),
            0xFF01 => Ok(Self::RenegotiationInfo),
            0x0010 => Ok(Self::ALPN),
            _ => Err(Error::Unknown("extension type")),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ServerExtensionPayload {
    KeyShareServer(KeyShareServer),
    SupportedVersionsServer(SupportedVersionsServer),
    KeyShareHelloRetryRequest(KeyShareHelloRetryRequest),
    RenegotiationInfo,
    ALPN(AlpnPayload),
}

impl ServerExtensionPayload {
    pub fn encode_payload(&self, buf: &mut BytesMut) {
        match self {
            Self::KeyShareServer(p) => p.encode(buf),
            Self::KeyShareHelloRetryRequest(p) => p.encode(buf),
            Self::SupportedVersionsServer(p) => p.encode(buf),
            Self::ALPN(p) => p.encode(buf),
            Self::RenegotiationInfo => (),
        }
    }

    pub fn decode_payload(extension_type: ServerExtensionType, buf: &mut BytesMut) -> Result<Self, Error> {
        match extension_type {
            ServerExtensionType::KeyShare => Ok(Self::KeyShareServer(KeyShareServer::decode(buf)?)),
            ServerExtensionType::SupportedVersions => Ok(Self::SupportedVersionsServer(SupportedVersionsServer::decode(buf)?)),
            ServerExtensionType::RenegotiationInfo => Ok(Self::RenegotiationInfo),
            ServerExtensionType::ALPN => Ok(Self::ALPN(AlpnPayload::decode(buf)?))
        }
    }
}

#[cfg(test)]
mod test_server_exts_parse {
    
}
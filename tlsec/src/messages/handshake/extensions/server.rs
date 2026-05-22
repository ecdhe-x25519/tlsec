use super::*;
use super::super::*;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerExtensionType {
    KeyShare = 0x0033,
    SupportedVersions = 0x002B,
    KeyShareHelloRetryRequest,
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
            _ => Err(Error::UnsupportedExtension),
        }
    }
}

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
            ServerExtensionType::KeyShareHelloRetryRequest => Ok(Self::KeyShareHelloRetryRequest(KeyShareHelloRetryRequest::decode(buf)?)),
            ServerExtensionType::ALPN => Ok(Self::ALPN(AlpnPayload::decode(buf)?))
        }
    }
}

pub struct SupportedVersionsServer {
    pub selected_version: Version,
}

impl Serialize for SupportedVersionsServer {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.selected_version as u16);
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let selected_version: Version = Version::try_from(buf.get_u16())?;

        Ok(Self { selected_version })
    }
}

pub struct KeyShareServer {
    pub server_share: KeyShareEntry,
}

impl Serialize for KeyShareServer {
    fn encode(&self, buf: &mut BytesMut) {
        self.server_share.encode(buf);
    }
    
    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        let server_share: KeyShareEntry = KeyShareEntry::decode(buf)?;
        Ok(Self { server_share })
    }
}

pub struct KeyShareHelloRetryRequest {
    pub selected_group: NamedGroup,
}

impl Serialize for KeyShareHelloRetryRequest {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.selected_group as u16);
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let selected_group: NamedGroup = NamedGroup::try_from(buf.get_u16())?;

        Ok(Self { selected_group })
    }
}
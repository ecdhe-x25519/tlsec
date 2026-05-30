use crate::message::*;
use crate::error::*;

use bytes::*;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientExtensionType {
    ServerName = 0x0000,
    SupportedGroups = 0x000A,
    SignatureAlgorithms = 0x000D,
    PSKKeyExchangeModes = 0x002D,
    StatusRequest = 0x0005,
    SignedCertificateTimestamp = 0x0012,
    CompressCertificate = 0x001B,
    ApplicationSettings = 0x44CD,
    EncryptedClientHello = 0xFE0D,
    EcPointFormats = 0x000B,
    ExtendedMainSecret = 0x0017,
    SessionTicket = 0x0023,
    KeyShare = 0x0033,
    SupportedVersions = 0x002B,
    ALPN = 0x0010,
    Grease,
}

impl TryFrom<u16> for ClientExtensionType {
    type Error = Error;
    
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0000 => Ok(Self::ServerName),
            0x0005 => Ok(Self::StatusRequest),
            0x000A => Ok(Self::SupportedGroups),
            0x000B => Ok(Self::EcPointFormats),
            0x000D => Ok(Self::SignatureAlgorithms),
            0x0010 => Ok(Self::ALPN),
            0x0012 => Ok(Self::SignedCertificateTimestamp),
            0x0017 => Ok(Self::ExtendedMainSecret),
            0x001B => Ok(Self::CompressCertificate),
            0x0023 => Ok(Self::SessionTicket),
            0x002B => Ok(Self::SupportedVersions),
            0x002D => Ok(Self::PSKKeyExchangeModes),
            0x0033 => Ok(Self::KeyShare),
            0x44CD => Ok(Self::ApplicationSettings),
            0xFE0D => Ok(Self::EncryptedClientHello),
            _ => if is_grease_u16(value) {
                Ok(Self::Grease)
            } else {
                Err(Error::Unknown("extension"))
            }
        }
    }
}

pub enum ClientExtensionPayload {
    ServerName(ServerNamePayload),
    SupportedGroups(SupportedGroupsPayload),
    SignatureAlgorithms(SignatureAlgorithmsPayload),
    PSKKeyExchangeModes(PskKeyExchangeModesPayload),
    StatusRequest,
    SignedCertificateTimestamp,
    CompressCertificate(CompressCertificatePayload),
    ApplicationSettings(ApplicationSettingsPayload),
    EncryptedClientHello(EncryptedClientHelloPayload),
    EcPointFormats(EcPointFormatsPayload),
    ExtendedMainSecret,
    SessionTicket,
    KeyShareClient(KeyShareClient),
    SupportedVersionsClient(SupportedVersionsClient),
    ALPN(AlpnPayload),
    Grease,
}

impl ClientExtensionPayload {
    pub fn encode_payload(&self, buf: &mut BytesMut) {
        match self {
            Self::ServerName(p) => p.encode(buf),
            Self::SupportedGroups(p) => p.encode(buf),
            Self::SignatureAlgorithms(p) => p.encode(buf),
            Self::ALPN(p) => p.encode(buf),
            Self::StatusRequest => {},
            Self::KeyShareClient(p) => p.encode(buf),
            Self::SupportedVersionsClient(p) => p.encode(buf),
            Self::PSKKeyExchangeModes(p) => p.encode(buf),
            Self::CompressCertificate(p) => p.encode(buf),
            Self::ApplicationSettings(p) => p.encode(buf),
            Self::EncryptedClientHello(p) => p.encode(buf),
            Self::EcPointFormats(p) => p.encode(buf),
            Self::Grease => {},
            Self::ExtendedMainSecret => {},
            Self::SessionTicket => {},
            Self::SignedCertificateTimestamp => {},
        }
    }

    pub fn decode_payload(extension_type: ClientExtensionType, buf: &mut BytesMut) -> Result<Self, Error> {
        match extension_type {
            ClientExtensionType::ServerName => Ok(Self::ServerName(ServerNamePayload::decode(buf)?)),
            ClientExtensionType::SupportedGroups => Ok(Self::SupportedGroups(SupportedGroupsPayload::decode(buf)?)),
            ClientExtensionType::SignatureAlgorithms => Ok(Self::SignatureAlgorithms(SignatureAlgorithmsPayload::decode(buf)?)),
            ClientExtensionType::ALPN => Ok(Self::ALPN(AlpnPayload::decode(buf)?)),
            ClientExtensionType::StatusRequest => Ok(Self::StatusRequest),
            ClientExtensionType::KeyShare => Ok(Self::KeyShareClient(KeyShareClient::decode(buf)?)),
            ClientExtensionType::SupportedVersions => Ok(Self::SupportedVersionsClient(SupportedVersionsClient::decode(buf)?)),
            ClientExtensionType::PSKKeyExchangeModes => Ok(Self::PSKKeyExchangeModes(PskKeyExchangeModesPayload::decode(buf)?)),
            ClientExtensionType::CompressCertificate => Ok(Self::CompressCertificate(CompressCertificatePayload::decode(buf)?)),
            ClientExtensionType::ApplicationSettings => Ok(Self::ApplicationSettings(ApplicationSettingsPayload::decode(buf)?)),
            ClientExtensionType::EncryptedClientHello => Ok(Self::EncryptedClientHello(EncryptedClientHelloPayload::decode(buf)?)),
            ClientExtensionType::EcPointFormats => Ok(Self::EcPointFormats(EcPointFormatsPayload::decode(buf)?)),
            ClientExtensionType::Grease => Ok(Self::Grease),
            ClientExtensionType::ExtendedMainSecret => Ok(Self::ExtendedMainSecret),
            ClientExtensionType::SessionTicket => Ok(Self::SessionTicket),
            ClientExtensionType::SignedCertificateTimestamp => Ok(Self::SignedCertificateTimestamp),
        }
    }
}

#[cfg(test)]
mod test_server_exts_parse {
    
}
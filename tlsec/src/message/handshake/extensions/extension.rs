use crate::message::handshake::grease::GreasePayloadU16;
use crate::message::serialize::Serialize;
use crate::error::*;
use super::*;

use bytes::*;
use brevno::*;

#[derive(Debug, PartialEq, Eq)]
pub struct Extension {
    pub extension_type: ExtensionType,
    pub payload: ExtensionPayload, // length = u16
}

impl Serialize for Extension {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.extension_type.into());

        let len_pos: usize = buf.len();
        buf.put_u16(0);

        self.payload.encode_payload(buf);

        let len: u16 = (buf.len() - len_pos - 2) as u16;
        buf[len_pos..len_pos+2].copy_from_slice(&len.to_be_bytes())
    }

    fn decode(buf: &mut BytesMut) -> TlsResult<Self> {
        if buf.remaining() < 2 {
            error!(format!("Incomplete data: need {} more bytes", (2 - buf.remaining())));
            return Err(TlsError::Incomplete(2 - buf.remaining()));
        }

        let extension_type: ExtensionType = ExtensionType::try_from(buf.get_u16())?;
        let length: usize = buf.get_u16() as usize;

        if buf.remaining() < length {
            error!(format!("Incomplete data: need {} more bytes", (length - buf.remaining())));
            return Err(TlsError::Incomplete(length - buf.remaining()));
        }

        let mut data_buf: BytesMut = buf.split_to(length);
        println!("{:?}", extension_type);
        println!("{}", data_buf.remaining());
        let payload: ExtensionPayload = ExtensionPayload::decode_payload(extension_type, &mut data_buf)?;

        Ok(Self {
            extension_type,
            payload,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionType {
    ServerName,
    SupportedGroups,
    SignatureAlgorithms,
    PSKKeyExchangeModes,
    StatusRequest,
    SignedCertificateTimestamp,
    CompressCertificate,
    ApplicationSettings,
    EncryptedClientHello,
    EcPointFormats,
    ExtendedMainSecret,
    SessionTicket,
    KeyShare,
    SupportedVersions,
    ALPN,
    RenegotiationInfo,
    Grease(GreasePayloadU16),
    Unknown(u16),
}

impl Into<u16> for ExtensionType {
    fn into(self) -> u16 {
        match self {
            Self::ServerName => 0x0000,
            Self::SupportedGroups => 0x000A,
            Self::SignatureAlgorithms => 0x000D,
            Self::PSKKeyExchangeModes => 0x002D,
            Self::StatusRequest => 0x0005,
            Self::SignedCertificateTimestamp => 0x0012,
            Self::CompressCertificate => 0x001B,
            Self::ApplicationSettings => 0x44CD,
            Self::EncryptedClientHello => 0xFE0D,
            Self::EcPointFormats => 0x000B,
            Self::ExtendedMainSecret => 0x0017,
            Self::SessionTicket => 0x0023,
            Self::KeyShare => 0x0033,
            Self::SupportedVersions => 0x002B,
            Self::ALPN => 0x0010,
            Self::RenegotiationInfo => 0xFF01,
            Self::Grease(g) => g.grease,
            Self::Unknown(e) => e,
        }
    }
}

impl TryFrom<u16> for ExtensionType {
    type Error = TlsError;

    fn try_from(value: u16) -> TlsResult<Self> {
        match value {
            0x0000 => Ok(Self::ServerName),
            0x000A => Ok(Self::SupportedGroups),
            0x000D => Ok(Self::SignatureAlgorithms),
            0x002D => Ok(Self::PSKKeyExchangeModes),
            0x0005 => Ok(Self::StatusRequest),
            0x0012 => Ok(Self::SignedCertificateTimestamp),
            0x001B => Ok(Self::CompressCertificate),
            0x44CD => Ok(Self::ApplicationSettings),
            0xFE0D => Ok(Self::EncryptedClientHello),
            0x000B => Ok(Self::EcPointFormats),
            0x0017 => Ok(Self::ExtendedMainSecret),
            0x0023 => Ok(Self::SessionTicket),
            0x0033 => Ok(Self::KeyShare),
            0x002B => Ok(Self::SupportedVersions),
            0x0010 => Ok(Self::ALPN),
            0xFF01 => Ok(Self::RenegotiationInfo),
            _ => match GreasePayloadU16::is_grease(value) {
                Ok(g) => Ok(Self::Grease(g)),
                Err(_) => {
                    warn!("Unknown extension");
                    Ok(Self::Unknown(value))
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ExtensionPayload {
    ServerName(ServerNamePayload),
    SupportedGroups(SupportedGroupsPayload),
    SignatureAlgorithms(SignatureAlgorithmsPayload),
    PSKKeyExchangeModes(PskKeyExchangeModesPayload),
    CompressCertificate(CompressCertificatePayload),
    ApplicationSettings(ApplicationSettingsPayload),
    EncryptedClientHello(EncryptedClientHelloPayload),
    EcPointFormats(EcPointFormatsPayload),
    KeyShare(KeySharePayload),
    SupportedVersions(SupportedVersionsPayload),
    ALPN(AlpnPayload),
    StatusRequest(StatusRequestPayload),
    SignedCertificateTimestamp(SignedCertificateTimestampPayload),
    RenegotiationInfo(RenegotiationInfoPayload),
    SessionTicket(SessionTicketPayload),
    ExtendedMainSecret,
    Grease(GreasePayloadU16),
    Unknown(UnknownExtension)
}

impl ExtensionPayload {
    pub fn encode_payload(&self, buf: &mut BytesMut) {
        match self {
            Self::ServerName(p) => p.encode(buf),
            Self::SupportedGroups(p) => p.encode(buf),
            Self::SignatureAlgorithms(p) => p.encode(buf),
            Self::ALPN(p) => p.encode(buf),
            Self::KeyShare(p) => p.encode(buf),
            Self::SupportedVersions(p) => p.encode(buf),
            Self::PSKKeyExchangeModes(p) => p.encode(buf),
            Self::CompressCertificate(p) => p.encode(buf),
            Self::ApplicationSettings(p) => p.encode(buf),
            Self::EncryptedClientHello(p) => p.encode(buf),
            Self::EcPointFormats(p) => p.encode(buf),
            Self::StatusRequest(p) => p.encode(buf),
            Self::SignedCertificateTimestamp(p) => p.encode(buf),
            Self::SessionTicket(p) => p.encode(buf),
            Self::ExtendedMainSecret => {},
            Self::RenegotiationInfo(p) => p.encode(buf),
            Self::Grease(p) => p.encode(buf),
            Self::Unknown(p) => p.encode(buf),
        }
    }

    pub fn decode_payload(extension_type: ExtensionType, buf: &mut BytesMut) -> TlsResult<Self> {
        match extension_type {
            ExtensionType::ServerName => Ok(Self::ServerName(ServerNamePayload::decode(buf)?)),
            ExtensionType::SupportedGroups => Ok(Self::SupportedGroups(SupportedGroupsPayload::decode(buf)?)),
            ExtensionType::SignatureAlgorithms => Ok(Self::SignatureAlgorithms(SignatureAlgorithmsPayload::decode(buf)?)),
            ExtensionType::ALPN => Ok(Self::ALPN(AlpnPayload::decode(buf)?)),
            ExtensionType::StatusRequest => Ok(Self::StatusRequest(StatusRequestPayload::decode(buf)?)),
            ExtensionType::KeyShare => Ok(Self::KeyShare(KeySharePayload::decode(buf)?)),
            ExtensionType::SupportedVersions => Ok(Self::SupportedVersions(SupportedVersionsPayload::decode(buf)?)),
            ExtensionType::PSKKeyExchangeModes => Ok(Self::PSKKeyExchangeModes(PskKeyExchangeModesPayload::decode(buf)?)),
            ExtensionType::CompressCertificate => Ok(Self::CompressCertificate(CompressCertificatePayload::decode(buf)?)),
            ExtensionType::ApplicationSettings => Ok(Self::ApplicationSettings(ApplicationSettingsPayload::decode(buf)?)),
            ExtensionType::EncryptedClientHello => Ok(Self::EncryptedClientHello(EncryptedClientHelloPayload::decode(buf)?)),
            ExtensionType::EcPointFormats => Ok(Self::EcPointFormats(EcPointFormatsPayload::decode(buf)?)),
            ExtensionType::RenegotiationInfo => Ok(Self::RenegotiationInfo(RenegotiationInfoPayload::decode(buf)?)),
            ExtensionType::SessionTicket => Ok(Self::SessionTicket(SessionTicketPayload::decode(buf)?)),
            ExtensionType::SignedCertificateTimestamp => Ok(Self::SignedCertificateTimestamp(SignedCertificateTimestampPayload::decode(buf)?)),
            ExtensionType::ExtendedMainSecret => Ok(Self::ExtendedMainSecret),
            ExtensionType::Grease(g) => Ok(Self::Grease(g)),
            ExtensionType::Unknown(_) => Ok(Self::Unknown(UnknownExtension::decode(buf)?)),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UnknownExtension {
    pub payload: Bytes,
}

impl Serialize for UnknownExtension {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_slice(&self.payload);
    }

    fn decode(buf: &mut BytesMut) -> TlsResult<Self> {
        if buf.remaining() == 0 {
            return Ok(Self { payload: Bytes::new() })
        }

        if buf.remaining() < 2 {
            error!(format!("Incomplete data: need {} more bytes", (2 - buf.remaining())));
            return Err(TlsError::Incomplete(2 - buf.remaining()));
        }

        let length = buf.get_u16();
        let len = length as usize;

        if buf.remaining() < len {
            error!(format!("Incomplete data: need {} more bytes", (len - buf.remaining())));
            return Err(TlsError::Incomplete(len - buf.remaining()));
        }

        let payload = buf.split_to(len).freeze();

        Ok(Self {
            payload,
        })
    }
}

#[cfg(test)]
mod test_extension_parse {
    
}
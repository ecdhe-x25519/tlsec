use super::*;
use super::super::*;

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
                Err(Error::Unknown("extensions"))
            }
        }
    }
}

pub enum ClientExtensionPayload {
    ServerName(ServerNamePayload),
    SupportedGroups(SupportedGroupsPayload),
    SignatureAlgorithms(SignatureAlgorithmsPayload),
    PSKKeyExchangeModes(PskKeyExchangeModesPayload),
    StatusRequest(StatusRequestPayload),
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
    Grease(GreasePayload),
}

impl ClientExtensionPayload {
    pub fn encode_payload(&self, buf: &mut BytesMut) {
        match self {
            Self::ServerName(p) => p.encode(buf),
            Self::SupportedGroups(p) => p.encode(buf),
            Self::SignatureAlgorithms(p) => p.encode(buf),
            Self::ALPN(p) => p.encode(buf),
            Self::StatusRequest(p) => p.encode(buf),
            Self::KeyShareClient(p) => p.encode(buf),
            Self::SupportedVersionsClient(p) => p.encode(buf),
            Self::PSKKeyExchangeModes(p) => p.encode(buf),
            Self::CompressCertificate(p) => p.encode(buf),
            Self::ApplicationSettings(p) => p.encode(buf),
            Self::EncryptedClientHello(p) => p.encode(buf),
            Self::EcPointFormats(p) => p.encode(buf),
            Self::Grease(p) => p.encode(buf),
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
            ClientExtensionType::StatusRequest => Ok(Self::StatusRequest(StatusRequestPayload::decode(buf)?)),
            ClientExtensionType::KeyShare => Ok(Self::KeyShareClient(KeyShareClient::decode(buf)?)),
            ClientExtensionType::SupportedVersions => Ok(Self::SupportedVersionsClient(SupportedVersionsClient::decode(buf)?)),
            ClientExtensionType::PSKKeyExchangeModes => Ok(Self::PSKKeyExchangeModes(PskKeyExchangeModesPayload::decode(buf)?)),
            ClientExtensionType::CompressCertificate => Ok(Self::CompressCertificate(CompressCertificatePayload::decode(buf)?)),
            ClientExtensionType::ApplicationSettings => Ok(Self::ApplicationSettings(ApplicationSettingsPayload::decode(buf)?)),
            ClientExtensionType::EncryptedClientHello => Ok(Self::EncryptedClientHello(EncryptedClientHelloPayload::decode(buf)?)),
            ClientExtensionType::EcPointFormats => Ok(Self::EcPointFormats(EcPointFormatsPayload::decode(buf)?)),
            ClientExtensionType::Grease => Ok(Self::Grease(GreasePayload::decode(buf)?)),
            ClientExtensionType::ExtendedMainSecret => Ok(Self::ExtendedMainSecret),
            ClientExtensionType::SessionTicket => Ok(Self::SessionTicket),
            ClientExtensionType::SignedCertificateTimestamp => Ok(Self::SignedCertificateTimestamp),
        }
    }
}

pub struct ServerNamePayload {
    pub name_type: NameType,
    pub name: String, // length = u16
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum NameType {
    HostName = 0x00,
}

impl TryFrom<u8> for NameType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::HostName),
            _ => Err(Error::Unknown("name type")),
        }
    }
}

impl Serialize for ServerNamePayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.name_type as u8);
        buf.put_u16(self.name.len() as u16);
        buf.put(BytesMut::from(self.name.as_str()));
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 1 {
            return Err(Error::Incomplete(1 - buf.remaining()))
        }

        let name_type: NameType = NameType::try_from(buf.get_u8())?;

        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()))
        }

        let name_length: usize = buf.get_u16() as usize;

        if buf.remaining() < name_length {
            return Err(Error::Incomplete(name_length - buf.remaining()))
        }

        let bytes: BytesMut = buf.split_to(name_length);
        let name: String = String::from_utf8(bytes.to_vec())
            .map_err(|e| Error::Io(format!("wrong sni: {e}")))?;

        Ok(Self {
            name_type,
            name,
        })
    }
}

pub struct SupportedGroupsPayload {
    pub groups: Vec<NamedGroup>, // length = u16
}

impl Serialize for SupportedGroupsPayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16((self.groups.len() * 2) as u16);
        for group in &self.groups {
            buf.put_u16(*group as u16);
        }
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()))
        }

        let list_length: usize = buf.get_u16() as usize;

        if buf.remaining() < list_length {
            return Err(Error::Incomplete(list_length - buf.remaining()))
        }

        let mut groups: Vec<NamedGroup> = Vec::new();
        for _ in 0..list_length / 2 {
            groups.push(NamedGroup::try_from(buf.get_u16())?);
        }

        Ok(Self {
            groups,
        })
    }
}

pub struct SignatureAlgorithmsPayload {
    pub schemes: Vec<SignatureScheme>, // length = u16
}

impl Serialize for SignatureAlgorithmsPayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16((self.schemes.len() * 2) as u16);
        for scheme in &self.schemes {
            buf.put_u16(*scheme as u16);
        }
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let list_length: usize = buf.get_u16() as usize;

        if buf.remaining() < list_length {
            return Err(Error::Incomplete(list_length - buf.remaining()));
        }

        let mut schemes: Vec<SignatureScheme> = Vec::new();
        for _ in 0..list_length / 2 {
            schemes.push(SignatureScheme::try_from(buf.get_u16())?);
        }

        Ok(Self { schemes })
    }
}

pub struct StatusRequestPayload {
    pub status_type: StatusType,
    pub responder_id_list: BytesMut, // length = u16
    pub request_extensions: BytesMut, // length = u16
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusType {
    Ocsp = 0x01,
}

impl TryFrom<u8> for StatusType {
    type Error = Error;
    
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(StatusType::Ocsp),
            _ => Err(Error::Unknown("status type")),
        }
    }
}

impl Serialize for StatusRequestPayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.status_type as u8);
        buf.put_u16(self.responder_id_list.len() as u16);
        buf.put_slice(&self.responder_id_list);
        buf.put_u16(self.request_extensions.len() as u16);
        buf.put_slice(&self.request_extensions);
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 1 {
            return Err(Error::Incomplete(1 - buf.remaining()));
        }

        let status_type: StatusType = StatusType::try_from(buf.get_u8())?;
        
        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let responder_len: usize = buf.get_u16() as usize;

        if buf.remaining() < responder_len {
            return Err(Error::Incomplete(responder_len - buf.remaining()));
        }

        let responder_id_list: BytesMut = buf.split_to(responder_len);
        
        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let ext_len: usize = buf.get_u16() as usize;

        if buf.remaining() < ext_len {
            return Err(Error::Incomplete(ext_len - buf.remaining()));
        }

        let request_extensions: BytesMut = buf.split_to(ext_len);
        
        Ok(Self {
            status_type,
            responder_id_list,
            request_extensions,
        })
    }
}

pub struct KeyShareClient {
    pub client_shares: Vec<KeyShareEntry>, // length = u16
}

impl Serialize for KeyShareClient {
    fn encode(&self, buf: &mut BytesMut) {
        let mut inner: BytesMut = BytesMut::new();
        for share in &self.client_shares {
            share.encode(&mut inner);
        }
        buf.put_u16(inner.len() as u16);
        buf.put_slice(&inner);
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let list_length: usize = buf.get_u16() as usize;

        if buf.remaining() < list_length {
            return Err(Error::Incomplete(list_length - buf.remaining()));
        }

        let mut data: BytesMut = buf.split_to(list_length);

        let mut client_shares: Vec<KeyShareEntry> = Vec::new();

        while data.has_remaining() {
            client_shares.push(KeyShareEntry::decode(&mut data)?);
        }

        Ok(Self { client_shares })
    }
}

pub struct SupportedVersionsClient {
    pub versions: Vec<Version>, // length = u8
}

impl Serialize for SupportedVersionsClient {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8((self.versions.len() * 2) as u8);
        for v in &self.versions {
            buf.put_u16(*v as u16);
        }
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 1 {
            return Err(Error::Incomplete(1 - buf.remaining()));
        }

        let list_length: usize = buf.get_u8() as usize;

        if buf.remaining() < list_length {
            return Err(Error::Incomplete(list_length - buf.remaining()));
        }

        let mut versions: Vec<Version> = Vec::new();

        for _ in 0..list_length / 2 {
            versions.push(Version::try_from(buf.get_u16())?);
        }

        Ok(Self { versions })
    }
}

pub struct PskKeyExchangeModesPayload {
    pub modes: Vec<PskKeyExchangeMode>, // length = u8
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PskKeyExchangeMode {
    PskKe = 0x00,
    PskDheKe = 0x01,
}

impl TryFrom<u8> for PskKeyExchangeMode {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::PskKe),
            0x01 => Ok(Self::PskDheKe),
            _ => Err(Error::Unknown("PSK exchange mode"))
        }
    }
}

impl Serialize for PskKeyExchangeModesPayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.modes.len() as u8);
        for mode in &self.modes {
            buf.put_u8(*mode as u8);
        }
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 1 {
            return Err(Error::Incomplete(1 - buf.remaining()));
        }
        
        let list_length: usize = buf.get_u8() as usize;

        if buf.remaining() < list_length {
            return Err(Error::Incomplete(list_length - buf.remaining()));
        }

        let mut modes: Vec<PskKeyExchangeMode> = Vec::new();

        for _ in 0..list_length {
            modes.push(PskKeyExchangeMode::try_from(buf.get_u8())?);
        }

        Ok(Self { modes })
    }
}

pub struct CompressCertificatePayload {
    pub algorithms: Vec<CompressionAlgorithm>, // length = u8
}

#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum CompressionAlgorithm {
    Zlib = 0x01,
    Brotli = 0x02,
}

impl TryFrom<u8> for CompressionAlgorithm {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Zlib),
            0x02 => Ok(Self::Brotli),
            _ => Err(Error::Unknown("compression algorithm"))
        }
    }
}

impl Serialize for CompressCertificatePayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.algorithms.len() as u8);
        for alg in &self.algorithms {
            buf.put_u16(*alg as u16);
        }
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 1 {
            return Err(Error::Incomplete(1 - buf.remaining()));
        }

        let list_length: usize = buf.get_u8() as usize;

        if buf.remaining() < list_length * 2 {
            return Err(Error::Incomplete(list_length * 2 - buf.remaining()));
        }

        let mut algorithms: Vec<CompressionAlgorithm> = Vec::new();

        for _ in 0..list_length {
            algorithms.push(CompressionAlgorithm::try_from(buf.get_u8())?);
        }

        Ok(Self { algorithms })
    }
}

pub struct ApplicationSettingsPayload {
    pub protocol: AlpnProtocols, // length = u8
    pub settings: BytesMut, // length = u16
}

impl Serialize for ApplicationSettingsPayload {
    fn encode(&self, buf: &mut BytesMut) {
        let proto_bytes = self.protocol.as_ref();
        buf.put_u8(proto_bytes.len() as u8);
        buf.put_slice(proto_bytes);
        buf.put_u16(self.settings.len() as u16);
        buf.put_slice(&self.settings);
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 1 {
            return Err(Error::Incomplete(1 - buf.remaining()));
        }

        let proto_len: usize = buf.get_u8() as usize;

        if buf.remaining() < proto_len {
            return Err(Error::Incomplete(proto_len - buf.remaining()));
        }

        let protocol_bytes: BytesMut = buf.split_to(proto_len);

        let protocol: AlpnProtocols = AlpnProtocols::try_from(protocol_bytes)?;
        
        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let settings_len: usize = buf.get_u16() as usize;

        if buf.remaining() < settings_len {
            return Err(Error::Incomplete(settings_len - buf.remaining()));
        }

        let settings: BytesMut = buf.split_to(settings_len);
        
        Ok(Self { protocol, settings })
    }
}

pub struct EncryptedClientHelloPayload {
    pub data: BytesMut,
}

impl Serialize for EncryptedClientHelloPayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_slice(&self.data);
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        let data: BytesMut = buf.split_to(buf.remaining());
        Ok(Self { data })
    }
}

pub struct EcPointFormatsPayload {
    pub formats: Vec<EcPointFormat>, // length = u8
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum EcPointFormat {
    Uncompressed = 0x00,
    AnsiX962CompressedPrime = 0x01,
    AnsiX962CompressedChar2 = 0x02,
}

impl TryFrom<u8> for EcPointFormat {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Uncompressed),
            0x01 => Ok(Self::AnsiX962CompressedPrime),
            0x02 => Ok(Self::AnsiX962CompressedChar2),
            _ => Err(Error::Unknown("EC point format"))
        }
    }
}

impl Serialize for EcPointFormatsPayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.formats.len() as u8);
        for format in &self.formats {
            buf.put_u8(*format as u8);
        }
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 1 {
            return Err(Error::Incomplete(1 - buf.remaining()));
        }

        let list_length: usize = buf.get_u8() as usize;

        if buf.remaining() < list_length {
            return Err(Error::Incomplete(list_length - buf.remaining()));
        }

        let mut formats: Vec<EcPointFormat> = Vec::new();

        for _ in 0..list_length {
            formats.push(EcPointFormat::try_from(buf.get_u8())?);
        }

        Ok(Self { formats })
    }
}

pub struct GreasePayload {
    pub data: BytesMut,
}

impl Serialize for GreasePayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_slice(&self.data);
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        let data: BytesMut = buf.split_to(buf.remaining());
        Ok(Self { data })
    }
}
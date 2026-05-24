use crate::supported::cipher::SupportedCipherSuite;

use super::handshake::handshake::HandshakeMessage;
use super::*;

pub struct Record {
    pub record_type: RecordType,
    pub legacy_version: Version,
    pub payload: RecordPayload, // length = u16
}

impl Record {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.record_type as u8);
        buf.put_u16(self.legacy_version as u16);

        let len_pos: usize = buf.len();
        buf.put_u16(0);

        self.payload.encode_payload(buf);

        let len: u16 = (buf.len() - len_pos - 2) as u16;
        buf[len_pos..len_pos+2].copy_from_slice(&len.to_be_bytes());
    }

    pub fn decode(buf: &mut BytesMut, cipher_suite: Option<&SupportedCipherSuite>) -> Result<Self, Error> {
        if buf.remaining() < 1 {
            return Err(Error::Incomplete(1 - buf.remaining()));
        }
        
        let record_type: RecordType = RecordType::try_from(buf.get_u8())?;

        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let legacy_version: Version = Version::try_from(buf.get_u16())?;

        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let length: usize = buf.get_u16() as usize;
        
        if buf.remaining() < length {
            return Err(Error::Incomplete(length - buf.remaining()));
        }

        let mut payload_buf: BytesMut = buf.split_to(length);
        let payload: RecordPayload = RecordPayload::decode_payload(record_type, &mut payload_buf, cipher_suite)?;
        
        Ok(Self {
            record_type,
            legacy_version,
            payload,
        })
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum RecordType {
    Alert = 21,
    HandshakeMessage = 22,
    ApplicationData = 23,
}

impl TryFrom<u8> for RecordType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Error> {
        match value {
            21 => Ok(Self::Alert),
            22 => Ok(Self::HandshakeMessage),
            23 => Ok(Self::ApplicationData),
            _ => Err(Error::Unknown("record type")),
        }
    }
}

pub enum RecordPayload {
    Handshake(Vec<HandshakeMessage>),
    Alert(AlertPayload),
    ApplicationData(BytesMut),
}

impl RecordPayload {
    pub fn encode_payload(&self, buf: &mut BytesMut) {
        match self {
            Self::Handshake(msgs) => {
                for msg in msgs {
                    msg.encode(buf);
                }
            }
            Self::Alert(alert) => {
                alert.encode(buf);
            }
            Self::ApplicationData(data) => {
                buf.put_slice(data);
            }
        }
    }

    pub fn decode_payload(record_type: RecordType, buf: &mut BytesMut, cipher_suite: Option<&SupportedCipherSuite>) -> Result<Self, Error> {
        match record_type {
            RecordType::HandshakeMessage => {
                let mut msgs: Vec<HandshakeMessage> = Vec::new();
                while buf.has_remaining() {
                    msgs.push(HandshakeMessage::decode(buf, cipher_suite)?);
                }
                Ok(RecordPayload::Handshake(msgs))
            }
            RecordType::Alert => {
                Ok(RecordPayload::Alert(AlertPayload::decode(buf)?))
            }
            RecordType::ApplicationData => {
                Ok(RecordPayload::ApplicationData(buf.split()))
            }
        }
    }
}

pub struct AlertPayload {
    pub level: AlertLevel,
    pub description: AlertDescription,
}

impl Serialize for AlertPayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.level as u8);
        buf.put_u8(self.description as u8);
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }
        
        let level: AlertLevel = AlertLevel::try_from(buf.get_u8())?;
        let description: AlertDescription = AlertDescription::try_from(buf.get_u8())?;
        
        Ok(AlertPayload {
            level,
            description,
        })
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertLevel {
    Warning = 1,
    Fatal = 2,
}

impl TryFrom<u8> for AlertLevel {
    type Error = Error;
    
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(AlertLevel::Warning),
            2 => Ok(AlertLevel::Fatal),
            _ => Err(Error::Unknown("alert level")),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertDescription {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    RecordOverflow = 22,
    HandshakeFailure = 40,
    BadCertificate = 42,
    UnsupportedCertificate = 43,
    CertificateRevoked = 44,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCa = 48,
    AccessDenied = 49,
    DecodeError = 50,
    DecryptError = 51,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    InappropriateFallback = 86,
    UserCanceled = 90,
    MissingExtension = 109,
    UnsupportedExtension = 110,
    UnrecognizedName = 112,
    BadCertificateStatusResponse = 113,
    UnknownPskIdentity = 115,
    CertificateRequired = 116,
    NoApplicationProtocol = 120,
}

impl TryFrom<u8> for AlertDescription {
    type Error = Error;
    
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(AlertDescription::CloseNotify),
            10 => Ok(AlertDescription::UnexpectedMessage),
            20 => Ok(AlertDescription::BadRecordMac),
            22 => Ok(AlertDescription::RecordOverflow),
            40 => Ok(AlertDescription::HandshakeFailure),
            42 => Ok(AlertDescription::BadCertificate),
            43 => Ok(AlertDescription::UnsupportedCertificate),
            44 => Ok(AlertDescription::CertificateRevoked),
            45 => Ok(AlertDescription::CertificateExpired),
            46 => Ok(AlertDescription::CertificateUnknown),
            47 => Ok(AlertDescription::IllegalParameter),
            48 => Ok(AlertDescription::UnknownCa),
            49 => Ok(AlertDescription::AccessDenied),
            50 => Ok(AlertDescription::DecodeError),
            51 => Ok(AlertDescription::DecryptError),
            70 => Ok(AlertDescription::ProtocolVersion),
            71 => Ok(AlertDescription::InsufficientSecurity),
            80 => Ok(AlertDescription::InternalError),
            86 => Ok(AlertDescription::InappropriateFallback),
            90 => Ok(AlertDescription::UserCanceled),
            109 => Ok(AlertDescription::MissingExtension),
            110 => Ok(AlertDescription::UnsupportedExtension),
            112 => Ok(AlertDescription::UnrecognizedName),
            113 => Ok(AlertDescription::BadCertificateStatusResponse),
            115 => Ok(AlertDescription::UnknownPskIdentity),
            116 => Ok(AlertDescription::CertificateRequired),
            120 => Ok(AlertDescription::NoApplicationProtocol),
            _ => Err(Error::Unknown("alert description")),
        }
    }
}
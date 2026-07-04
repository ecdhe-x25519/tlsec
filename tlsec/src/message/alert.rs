use crate::message::serialize::Serialize;
use crate::error::*;

use bytes::*;

use brevno::error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlertPayload {
    pub level: AlertLevel,
    pub description: AlertDescription,
}

impl Serialize for AlertPayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.level as u8);
        buf.put_u8(self.description as u8);
    }

    fn decode(buf: &mut BytesMut) -> TlsResult<Self> {
        if buf.remaining() < 2 {
            error!(format!("Incomplete data: need {} more bytes", (2 - buf.remaining())));
            return Err(TlsError::Incomplete(2 - buf.remaining()));
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
    Warning = 0x01,
    Fatal = 0x02,
}

impl TryFrom<u8> for AlertLevel {
    type Error = TlsError;
    
    fn try_from(value: u8) -> TlsResult<Self> {
        match value {
            0x01 => Ok(AlertLevel::Warning),
            0x02 => Ok(AlertLevel::Fatal),
            _ => {
                return Err(TlsError::Unknown("alert level"));
            }
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertDescription {
    CloseNotify = 0x00,
    UnexpectedMessage = 0x0A,
    BadRecordMac = 0x14,
    RecordOverflow = 0x16,
    HandshakeFailure = 0x28,
    BadCertificate = 0x2A,
    UnsupportedCertificate = 0x2B,
    CertificateRevoked = 0x2C,
    CertificateExpired = 0x2D,
    CertificateUnknown = 0x2E,
    IllegalParameter = 0x2F,
    UnknownCa = 0x30,
    AccessDenied = 0x31,
    DecodeTlsError = 0x32,
    DecryptTlsError = 0x33,
    ProtocolVersion = 0x46,
    InsufficientSecurity = 0x47,
    InternalTlsError = 0x50,
    InappropriateFallback = 0x56,
    UserCanceled = 0x5A,
    MissingExtension = 0x6D,
    UnsupportedExtension = 0x6E,
    UnrecognizedName = 0x70,
    BadCertificateStatusResponse = 0x71,
    UnknownPskIdentity = 0x73,
    CertificateRequired = 0x74,
    NoApplicationProtocol = 0x78,
}

impl TryFrom<u8> for AlertDescription {
    type Error = TlsError;
    
    fn try_from(value: u8) -> TlsResult<Self> {
        match value {
            0x00 => Ok(AlertDescription::CloseNotify),
            0x0A => Ok(AlertDescription::UnexpectedMessage),
            0x14 => Ok(AlertDescription::BadRecordMac),
            0x16 => Ok(AlertDescription::RecordOverflow),
            0x28 => Ok(AlertDescription::HandshakeFailure),
            0x2A => Ok(AlertDescription::BadCertificate),
            0x2B => Ok(AlertDescription::UnsupportedCertificate),
            0x2C => Ok(AlertDescription::CertificateRevoked),
            0x2D => Ok(AlertDescription::CertificateExpired),
            0x2E => Ok(AlertDescription::CertificateUnknown),
            0x2F => Ok(AlertDescription::IllegalParameter),
            0x30 => Ok(AlertDescription::UnknownCa),
            0x31 => Ok(AlertDescription::AccessDenied),
            0x32 => Ok(AlertDescription::DecodeTlsError),
            0x33 => Ok(AlertDescription::DecryptTlsError),
            0x46 => Ok(AlertDescription::ProtocolVersion),
            0x47 => Ok(AlertDescription::InsufficientSecurity),
            0x50 => Ok(AlertDescription::InternalTlsError),
            0x56 => Ok(AlertDescription::InappropriateFallback),
            0x5A => Ok(AlertDescription::UserCanceled),
            0x6D => Ok(AlertDescription::MissingExtension),
            0x6E => Ok(AlertDescription::UnsupportedExtension),
            0x70 => Ok(AlertDescription::UnrecognizedName),
            0x71 => Ok(AlertDescription::BadCertificateStatusResponse),
            0x73 => Ok(AlertDescription::UnknownPskIdentity),
            0x74 => Ok(AlertDescription::CertificateRequired),
            0x78 => Ok(AlertDescription::NoApplicationProtocol),
            _ => Err(TlsError::Unknown("alert description")),
        }
    }
}

#[cfg(test)]
mod test_alert_parse {
    use super::*;

    #[test]
    fn alert_parse() {
        let mut buf: BytesMut = BytesMut::new();

        let alert: AlertPayload = AlertPayload {
            level: AlertLevel::Fatal,
            description: AlertDescription::AccessDenied,
        };

        alert.encode(&mut buf);

        let decoded: AlertPayload = AlertPayload::decode(&mut buf).unwrap();

        assert_eq!(alert, decoded);
    }
}
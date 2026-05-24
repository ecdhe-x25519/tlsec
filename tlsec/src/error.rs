use std::fmt;

use crate::messages::record::{AlertDescription, AlertPayload, Record};
use crate::messages::record::RecordType::Alert;
use crate::messages::record::RecordPayload;
use crate::messages::Version::Tls12;
use crate::messages::record::AlertLevel::Fatal;

#[derive(Debug)]
pub enum Error {
    Unknown(&'static str),
    Unsupported(&'static str),
    Alert(AlertDescription),
    Incomplete(usize),
    Crypto(String),
    Io(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(msg) => write!(f, "{}", msg),
            Self::Unsupported(msg) => write!(f, "{}", msg),
            Self::Alert(msg) => write!(f, "Alert received: {:?}", msg),
            Self::Incomplete(msg) => write!(f, "Incomplete data: need {} more bytes", msg),
            Self::Crypto(msg) => write!(f, "Crypto error: {}", msg),
            Self::Io(msg) => write!(f, "IO error: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    pub fn handle_webpki(error: webpki::Error) -> AlertDescription {
        match error {
            webpki::Error::BadDer => AlertDescription::BadCertificate,
            webpki::Error::BadDerTime => AlertDescription::BadCertificate,
            webpki::Error::CaUsedAsEndEntity => AlertDescription::BadCertificate,
            webpki::Error::CertExpired => AlertDescription::CertificateExpired,
            webpki::Error::CertNotValidForName => AlertDescription::CertificateUnknown,
            webpki::Error::CertNotValidYet => AlertDescription::BadCertificate,
            webpki::Error::EndEntityUsedAsCa => AlertDescription::BadCertificate,
            webpki::Error::ExtensionValueInvalid => AlertDescription::CertificateUnknown,
            webpki::Error::InvalidCertValidity => AlertDescription::CertificateUnknown,
            webpki::Error::InvalidSignatureForPublicKey => AlertDescription::CertificateUnknown,
            webpki::Error::NameConstraintViolation => AlertDescription::CertificateUnknown,
            webpki::Error::PathLenConstraintViolated => AlertDescription::CertificateUnknown,
            webpki::Error::SignatureAlgorithmMismatch => AlertDescription::BadCertificate,
            webpki::Error::RequiredEkuNotFound => AlertDescription::CertificateUnknown,
            webpki::Error::UnknownIssuer => AlertDescription::UnknownCa,
            webpki::Error::UnsupportedCertVersion => AlertDescription::UnsupportedCertificate,
            webpki::Error::MissingOrMalformedExtensions => AlertDescription::CertificateUnknown,
            webpki::Error::UnsupportedCriticalExtension => AlertDescription::UnsupportedCertificate,
            webpki::Error::UnsupportedSignatureAlgorithmForPublicKey => AlertDescription::UnsupportedCertificate,
            webpki::Error::UnsupportedSignatureAlgorithm => AlertDescription::UnsupportedCertificate,
        }
    }
}

pub fn build_alert(error: AlertDescription) -> Record {
    let alert_message: AlertPayload = AlertPayload {
        level: Fatal,
        description: error,
    };

    let record: Record = Record {
        record_type: Alert,
        legacy_version: Tls12,
        payload: RecordPayload::Alert(alert_message),
    };

    record
}
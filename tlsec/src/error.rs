use std::fmt;

pub use crate::message::alert::*;
use crate::message::record::*;
use crate::message::version::Version;

pub type TlsResult<T> = Result<T, TlsError>;

#[derive(Debug)]
pub enum TlsError {
    Unknown,
    Unsupported,
    Alert(AlertDescription),
    Incomplete(usize),
    Crypto,
    Io,
}

impl fmt::Display for TlsError {
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

impl TlsError {
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

pub(crate) fn build_alert(error: AlertDescription) -> Record {
    let alert_message: AlertPayload = AlertPayload {
        level: AlertLevel::Fatal,
        description: error,
    };

    let record: Record = Record {
        record_type: RecordType::Alert,
        legacy_version: Version::Tls12,
        payload: RecordPayload::Alert(alert_message),
    };

    record
}

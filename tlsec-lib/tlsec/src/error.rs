use std::fmt;

#[derive(Debug)]
pub enum Error {
    UnsupportedCipherSuite,
    UnsupportedVersion,
    UnsupportedExtension,
    UnsupportedGroup,
    UnsupportedNamedGroup,
    UnsupportedCompressionMethod,
    UnsupportedSignatureScheme,
    UnsupportedEcPointFormat,
    UnsupportedCompressionAlgorithm,
    UnsupportedNameType,
    UnsupportedALPN,
    UnsupportedRecordType,
    UnsupportedHandshakeType,
    UnexpectedMessage,
    AlertReceived,
    UnknownMessage,
    InvalidCertificate,
    MissingExtension,
    Incomplete(usize),
    Handshake(&'static str),
    Crypto(String),
    Io(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnsupportedCipherSuite => write!(f, "Unsupported cipher suite"),
            Error::UnsupportedVersion => write!(f, "Unsupported TLS version"),
            Error::UnsupportedExtension => write!(f, "Unsupported extension"),
            Error::UnsupportedGroup => write!(f, "Unsupported named group"),
            Error::UnsupportedNamedGroup => write!(f, "Unsupported named group"),
            Error::UnsupportedCompressionMethod => write!(f, "Unsupported compression method"),
            Error::UnsupportedSignatureScheme => write!(f, "Unsupported signature scheme"),
            Error::UnsupportedEcPointFormat => write!(f, "Unsupported EC point format"),
            Error::UnsupportedCompressionAlgorithm => write!(f, "Unsupported compression algorithm"),
            Error::UnsupportedNameType => write!(f, "Unsupported name type"),
            Error::UnsupportedALPN => write!(f, "Unsupported ALPN protocol"),
            Error::UnsupportedRecordType => write!(f, "Unsupported record type"),
            Error::UnsupportedHandshakeType => write!(f, "Unsupported handshake type"),
            Error::UnexpectedMessage => write!(f, "Unexpected message"),
            Error::AlertReceived => write!(f, "Alert received"),
            Error::UnknownMessage => write!(f, "Unknown message"),
            Error::InvalidCertificate => write!(f, "Invalid certificate"),
            Error::MissingExtension => write!(f, "Extension missing"),
            Error::Incomplete(n) => write!(f, "Incomplete data: need {} more bytes", n),
            Error::Crypto(msg) => write!(f, "Crypto error: {}", msg),
            Error::Handshake(msg) => write!(f, "Handshake error: {}", msg),
            Error::Io(msg) => write!(f, "IO error: {}", msg),
        }
    }
}

impl std::error::Error for Error {}
use crate::certificate::cert_store::{CertStore, Der};
use crate::message::handshake::certificate::sig_scheme::SupportedScheme;
use crate::message::handshake::extensions::client::ec_point_format::SupportedEcPointFormat;
use crate::message::handshake::extensions::client::psk::PskKeyExchangeMode;
use crate::message::handshake::extensions::compression_algo::SupportedCompressionAlgorithm;
use crate::message::handshake::extensions::key_share::SupportedNamedGroup;
use crate::message::handshake::hello::cipher_suite::SupportedCipherSuite;
use crate::message::handshake::hello::client::ClientHelloPayload;
use crate::message::handshake::hello::compression_method::SupportedCompressionMethod;
use crate::message::handshake::hello::server::ServerHelloPayload;
use crate::message::version::SupportedVersion;

pub struct CommonConfig {
    pub supported_versions: Vec<SupportedVersion>,
    pub supported_cipher_suites: Vec<SupportedCipherSuite>,
    pub supported_compression_method: Vec<SupportedCompressionMethod>,
    pub supported_named_groups: Vec<SupportedNamedGroup>,
    pub supported_signature_schemes: Vec<SupportedScheme>,
    pub supported_compression_algorithms: Vec<SupportedCompressionAlgorithm>,
    pub supported_formats: Vec<SupportedEcPointFormat>,
    pub cert_root: Option<CertStore>,
    pub server_name: Option<String>,
    pub cert: Option<Der>,
    pub psk_ke_mode: Option<PskKeyExchangeMode>,
}

pub struct ClientConfig {
    pub common: CommonConfig,
    pub client_hello: ClientHelloPayload,
    pub psk: Option<PskIdentity>,
    pub verify_dns: bool,
}

pub struct ServerConfig {
    pub common: CommonConfig,
    pub server_hello: ServerHelloPayload,
    pub client_auth_mode: ClientAuthMode,
    pub psk_identities_path: Option<Vec<PskIdentity>>,
}

pub struct PskIdentity {
    pub identity: Vec<u8>,
    pub psk: Vec<u8>,
}

pub enum ClientAuthMode {
    None,
    Require,
}
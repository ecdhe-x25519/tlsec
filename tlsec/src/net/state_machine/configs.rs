use crate::messages::handshake::extensions::client::PskKeyExchangeMode;
use crate::messages::handshake::handshake::client::ClientHelloPayload;
use crate::messages::handshake::handshake::server::ServerHelloPayload;

use crate::supported::cipher::SupportedCipherSuite;
use crate::supported::compression_algorithm::SupportedCompressionAlgorithm;
use crate::supported::compression_method::SupportedCompressionMethod;
use crate::supported::ec_point_format::SupportedEcPointFormat;
use crate::supported::named_group::SupportedNamedGroup;
use crate::supported::signature::SupportedScheme;
use crate::supported::version::SupportedVersion;

pub struct CommonConfig {
    pub supported_versions: Vec<SupportedVersion>,
    pub supported_cipher_suites: Vec<SupportedCipherSuite>,
    pub supported_compression_method: Vec<SupportedCompressionMethod>,
    pub supported_named_groups: Vec<SupportedNamedGroup>,
    pub supported_signature_schemes: Vec<SupportedScheme>,
    pub supported_compression_algorithms: Vec<SupportedCompressionAlgorithm>,
    pub supported_formats: Vec<SupportedEcPointFormat>,
}

pub struct ClientConfig {
    pub common: CommonConfig,
    pub client_hello: ClientHelloPayload,
    pub cert_path: Option<String>,
    pub psk: Option<PskIdentitie>,
}

pub struct ServerConfig {
    pub common: CommonConfig,
    pub server_hello: ServerHelloPayload,
    pub client_auth_mode: ClientAuthMode,
    pub server_name: Option<String>,
    pub cert_path: Option<String>,
    pub psk_identities: Option<Vec<PskIdentitie>>,
    pub psk_ke_mode: Option<PskKeyExchangeMode>,
}

pub struct PskIdentitie {
    pub identity: Vec<u8>,
    pub psk: Vec<u8>,
}

pub enum ClientAuthMode {
    None,
    Request,
    Require,
}
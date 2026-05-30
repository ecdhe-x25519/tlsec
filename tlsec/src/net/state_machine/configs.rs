use crate::message::*;

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
    pub cert_root_path: Option<String>,
    pub client_cert_path: Option<String>,
    pub psk: Option<PskIdentity>,
    pub server_name: Option<String>,
    pub verify_dns: bool,
}

pub struct ServerConfig {
    pub common: CommonConfig,
    pub server_hello: ServerHelloPayload,
    pub client_auth_mode: ClientAuthMode,
    pub server_name: Option<String>,
    pub cert_root_path: Option<String>,
    pub server_cert_path: Option<String>,
    pub psk_path: Option<String>,
    pub psk_identities: Option<Vec<PskIdentity>>,
    pub psk_ke_mode: Option<PskKeyExchangeMode>,
}

pub struct PskIdentity {
    pub identity: Vec<u8>,
    pub psk: Vec<u8>,
}

pub enum ClientAuthMode {
    None,
    Require,
}
use crate::messages::Version;
use crate::messages::handshake::{CipherSuite, NamedGroup, SignatureScheme};
use crate::messages::handshake::handshake::client::ClientHelloPayload;
use crate::messages::handshake::handshake::server::ServerHelloPayload;

pub struct CommonConfig {
    pub supported_version: Version,
    pub supported_cipher_suites: Vec<CipherSuite>,
    pub supported_named_groups: NamedGroup,
    pub supported_signature_scheme: SignatureScheme,
}

pub struct ClientConfig {
    pub common: CommonConfig,
    pub client_hello: ClientHelloPayload,
    pub cert_path: Option<String>,
    pub pre_shared_key: Option<Vec<u8>>,
}

pub struct ServerConfig {
    pub common: CommonConfig,
    pub server_hello: ServerHelloPayload,
    pub client_auth_mode: ClientAuthMode,
    pub server_name: Option<String>,
    pub cert_path: Option<String>,
    pub psk_id_path: Option<String>,
}

pub enum ClientAuthMode {
    None,
    Request,
    Require,
}
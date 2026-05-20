use crate::encryption::supported_suites::SupportedCipherSuite;

use crate::messages::handshake::extensions::AlpnProtocols;
use crate::messages::handshake::handshake::client::ClientHelloPayload;
use crate::messages::handshake::handshake::server::ServerHelloPayload;

pub struct CommonConfig {
    pub cipher_suites: Vec<SupportedCipherSuite>,
    pub alpn_protocols: Vec<AlpnProtocols>,
    pub max_fragment_size: Option<usize>,
}

pub struct ClientConfig {
    pub common: CommonConfig,
    pub server_name: String,
    pub cert_path: Option<String>,
    pub pre_shared_key: Option<Vec<u8>>,
    pub client_hello: ClientHelloPayload,
}

pub struct ServerConfig {
    pub common: CommonConfig,
    pub client_auth: ClientAuthMode,
    pub cert_path: Option<String>,
    pub server_hello: ServerHelloPayload,
    pub psk_identities_path: String,
}

pub enum ClientAuthMode {
    None,
    Request,
    Require,
}
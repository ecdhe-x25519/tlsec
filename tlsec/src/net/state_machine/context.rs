use crate::encryption::cipher_suite::{ApplicationKeys, HandshakeKeys};

use crate::messages::handshake::extensions::AlpnProtocols;
use crate::messages::handshake::handshake::client::ClientHelloPayload;
use crate::messages::handshake::handshake::server::ServerHelloPayload;

use crate::net::state_machine::configs::ClientAuthMode;

use crate::supported::cipher::SupportedCipherSuite;

use super::state::CommonState;

use super::*;

pub struct Context<S: Side> {
    pub common: CommonState,
    pub config: S::Config,
    pub side: S,
}

impl Context<ClientSide> {
    pub fn new_client(config: ClientConfig) -> Self {
        Self {
            common: CommonState::new(),
            config,
            side: ClientSide,
        }
    }

    pub fn get_cert_path(&self) -> Option<&str> {
        self.config.cert_path.as_deref()
    }

    pub fn get_client_hello(&self) -> &ClientHelloPayload {
        &self.config.client_hello
    }

    pub fn get_pre_shared_key(&self) -> Option<&[u8]> {
        self.config.pre_shared_key.as_deref()
    }
}

impl Context<ServerSide> {
    pub fn new_server(config: ServerConfig) -> Self {
        Self {
            common: CommonState::new(),
            config,
            side: ServerSide,
        }
    }

    pub fn get_cert_path(&self) -> Option<&str> {
        self.config.cert_path.as_deref()
    }

    pub fn get_server_hello(&self) -> &ServerHelloPayload {
        &self.config.server_hello
    }

    pub fn get_psk_identities_path(&self) -> Option<&str> {
        self.config.psk_id_path.as_deref()
    }

    pub fn get_client_auth_mode(&self) -> &ClientAuthMode {
        &self.config.client_auth_mode
    }
}

impl<S: Side> Context<S> {
    pub fn is_client(&self) -> bool {
        std::any::TypeId::of::<S>() == std::any::TypeId::of::<ClientSide>()
    }
    
    pub fn is_server(&self) -> bool {
        std::any::TypeId::of::<S>() == std::any::TypeId::of::<ServerSide>()
    }
    
    pub fn update_transcript(&mut self, data: &[u8]) {
        self.common.transcript.update(data);
    }
    
    pub fn set_cipher_suite(&mut self, cs: SupportedCipherSuite) {
        self.common.cipher_suite = Some(cs);
    }
    
    pub fn set_handshake_keys(&mut self, keys: HandshakeKeys) {
        self.common.handshake_keys = Some(keys);
    }
    
    pub fn set_application_keys(&mut self, keys: ApplicationKeys) {
        self.common.application_keys = Some(keys);
    }
    
    pub fn set_alpn_protocol(&mut self, proto: AlpnProtocols) {
        self.common.alpn_protocol = Some(proto);
    }
    
    pub fn set_handshake_complete(&mut self) {
        self.common.handshake_complete = true;
    }
    
    pub fn is_handshake_complete(&self) -> bool {
        self.common.handshake_complete
    }
    
    pub fn set_error(&mut self, err: Error) {
        self.common.set_error(err);
    }
}
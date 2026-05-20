use crate::encryption::supported_suites::{ApplicationKeys, HandshakeKeys, SupportedCipherSuite};

use crate::messages::handshake::extensions::AlpnProtocols;

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
}

impl Context<ServerSide> {
    pub fn new_server(config: ServerConfig) -> Self {
        Self {
            common: CommonState::new(),
            config,
            side: ServerSide,
        }
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
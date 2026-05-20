use crate::encryption::supported_suites::{SupportedCipherSuite, HandshakeKeys, ApplicationKeys};
use crate::encryption::transcript::TranscriptHash;

use crate::messages::handshake::extensions::AlpnProtocols;
use crate::messages::handshake::handshake::HandshakeMessage;

use super::context::Context;
use super::record_layer::RecordLayer;

use ring::digest::SHA256;

use super::*;

pub struct CommonState {
    pub record_layer: RecordLayer,
    pub transcript: TranscriptHash,
    pub cipher_suite: Option<SupportedCipherSuite>,
    pub handshake_keys: Option<HandshakeKeys>,
    pub application_keys: Option<ApplicationKeys>,
    pub alpn_protocol: Option<AlpnProtocols>,
    pub error: Option<Error>,
    pub handshake_complete: bool,
    pub closed: bool,
}

impl CommonState {
    pub fn new() -> Self {
        Self {
            record_layer: RecordLayer::new(),
            transcript: TranscriptHash::new(&SHA256),
            cipher_suite: None,
            handshake_keys: None,
            application_keys: None,
            alpn_protocol: None,
            error: None,
            handshake_complete: false,
            closed: false,
        }
    }
    
    pub fn is_handshake_complete(&self) -> bool {
        self.handshake_complete
    }
    
    pub fn set_handshake_complete(&mut self) {
        self.handshake_complete = true;
    }
    
    pub fn set_error(&mut self, err: Error) {
        self.error = Some(err);
        self.closed = true;
    }
}

pub trait State<S: Side>: Send + Sync + 'static {
    fn handle(
        self: Box<Self>,
        ctx: &mut Context<S>,
        msg: HandshakeMessage,
    ) -> Result<NextState<S>, Error>;
}

pub struct NextState<S: Side> {
    pub state: Box<dyn State<S>>,
    pub output: Option<BytesMut>,
}

impl<S: Side> NextState<S> {
    pub fn new<T: State<S> + 'static>(state: T, output: Option<BytesMut>) -> Self {
        Self {
            state: Box::new(state),
            output,
        }
    }
}
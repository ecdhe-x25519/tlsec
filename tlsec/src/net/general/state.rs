use crate::{
    encryption::transcript::TranscriptHash, message::handshake::{
        hello::SupportedCipherSuite, messages::HandshakeMessage,
    }, net::connection::record_layer::RecordLayer,
};

use super::{
    super::{
        negotiation::negotiated::*,
    },

    side::*,
    context::*,
};

use crate::error::*;

pub struct CommonState {
    pub transcript: TranscriptHash,
    pub negotiated: NegotiationState,
}

impl CommonState {
    pub fn new(cipher: &SupportedCipherSuite) -> TlsResult<Self> {
        Ok(Self {
            transcript: TranscriptHash::new(cipher.hash_algorithm()),
            negotiated: NegotiationState::new(),
        })
    }
}

pub trait ConnState<S: Side>: Send + Sync + 'static {
    fn handle(
        self: Box<Self>,
        ctx: &mut Context<S>,
        record_layer: &mut RecordLayer,
        msg: HandshakeMessage,
    ) -> TlsResult<NextState<S>>;

    fn finished(&self) -> bool;
}

pub struct NextState<S: Side> {
    pub state: Box<dyn ConnState<S>>,
    pub output: Option<Vec<HandshakeMessage>>,
}

impl<S: Side> NextState<S> {
    pub fn new<T: ConnState<S> + 'static>(state: T, output: Option<Vec<HandshakeMessage>>) -> Self {
        Self {
            state: Box::new(state),
            output,
        }
    }
}
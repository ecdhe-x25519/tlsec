use crate::encryption::key_schedule::{HandshakeKeys, ApplicationKeys};
use crate::encryption::transcript::TranscriptHash;
use crate::encryption::key_exchange::{compute_shared_secret, generate_key_pair};

use crate::messages::handshake::extensions::AlpnProtocols;
use crate::messages::handshake::handshake::HandshakeMessage;

use crate::supported::compression_algorithm::SupportedCompressionAlgorithm;
use crate::supported::compression_method::SupportedCompressionMethod;
use crate::supported::ec_point_format::SupportedEcPointFormat;
use crate::supported::named_group::SupportedNamedGroup;
use crate::supported::signature::SupportedScheme;
use crate::supported::version::SupportedVersion;
use crate::supported::cipher::SupportedCipherSuite;

use super::context::Context;

use super::record_layer::RecordLayer;

use crate::error::Error;

use super::*;

use ring::digest::SHA256;

use bytes::BytesMut;

pub struct CommonState {
    pub record_layer: RecordLayer,
    pub transcript: TranscriptHash,
    pub version: Option<SupportedVersion>,
    pub cipher_suite: Option<SupportedCipherSuite>,
    pub handshake_keys: Option<HandshakeKeys>,
    pub application_keys: Option<ApplicationKeys>,
    pub alpn_protocol: Option<AlpnProtocols>,
    pub named_group: Option<SupportedNamedGroup>,
    pub ec_point_format: Option<SupportedEcPointFormat>,
    pub compression_method: Option<SupportedCompressionMethod>,
    pub compression_algorithm: Option<SupportedCompressionAlgorithm>,
    pub signature_scheme: Option<SupportedScheme>,
    pub psk: Option<Vec<u8>>,
    pub pbk: Option<BytesMut>,
    pub error: Option<Error>,
    pub handshake_complete: bool,
    pub closed: bool,
}

impl CommonState {
    pub fn new() -> Self {
        Self {
            record_layer: RecordLayer::new(),
            transcript: TranscriptHash::new(&SHA256),
            version: None,
            cipher_suite: None,
            handshake_keys: None,
            application_keys: None,
            alpn_protocol: None,
            named_group: None,
            ec_point_format: None,
            compression_method: None,
            compression_algorithm: None,
            signature_scheme: None,
            psk: None,
            pbk: None,
            error: None,
            handshake_complete: false,
            closed: false,
        }
    }

    pub fn set_handshake_keys(&mut self) {
        self.handshake_keys = Some(HandshakeKeys::derive_handshake_keys(
            &self.cipher_suite,
            &self.psk,
            &self.pbk,
            &self.transcript)?
        )
    }

    pub fn set_application_keys(&mut self) {
        self.application_keys = Some(ApplicationKeys::derive_application_keys(
            &self.cipher_suite,
            &self.psk,
            &self.pbk)?
        )
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
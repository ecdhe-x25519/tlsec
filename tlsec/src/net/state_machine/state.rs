use crate::encryption::*;

use crate::message::*;

use super::context::Context;

use super::record_layer::RecordLayer;

use crate::error::Error;

use super::*;

use ring::agreement::EphemeralPrivateKey;
use ring::digest::SHA256;

use bytes::*;

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
    pub private_key: Option<EphemeralPrivateKey>,
    pub public_key: Option<Vec<u8>>,
    pub shared_key: Option<Vec<u8>>,
    pub pre_shared_key: Option<Vec<u8>>,
    pub peer_public_key: Option<Bytes>,
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
            pre_shared_key: None,
            peer_public_key: None,
            private_key: None,
            public_key: None,
            shared_key: None,
            error: None,
            handshake_complete: false,
            closed: false,
        }
    }

    fn gen_keypair(&mut self) -> Result<(), Error> {
        let algo: SupportedNamedGroup = self.named_group
            .ok_or(Error::Alert(AlertDescription::HandshakeFailure))?;

        let rand: &Random = get_random();
        let (private_key, public_key) = generate_key_pair(rand, &algo)?;

        self.private_key = Some(private_key);
        self.public_key = Some(public_key.as_ref().to_vec());

        Ok(())
    }

    fn compute_secret(&mut self) -> Result<(), Error> {
        let private_key: EphemeralPrivateKey = self.private_key.take()
            .ok_or(Error::Alert(AlertDescription::HandshakeFailure))?;
        let peer_public_key: Bytes = self.peer_public_key.take()
            .ok_or(Error::Alert(AlertDescription::HandshakeFailure))?;
        let algo: SupportedNamedGroup = self.named_group
            .ok_or(Error::Alert(AlertDescription::HandshakeFailure))?;

        let shared: Vec<u8> = compute_shared_secret(private_key, &peer_public_key, algo.to_curve())?;

        self.shared_key = Some(shared);

        Ok(())
    }

    pub fn set_handshake_keys(&mut self) -> Result<(), Error> {
        let cipher_suite: &SupportedCipherSuite = self.cipher_suite.as_ref()
            .ok_or(Error::Crypto(format!("cipher suite is not set")))?;

        let mut psk: Option<&[u8]> = None;

        if let Some(k) = &self.pre_shared_key {
            psk = Some(&k.as_slice())
        };

        let pbk: &Bytes = self.peer_public_key.as_ref()
            .ok_or(Error::Crypto(format!("pbk is not set")))?;

        let transcript: &TranscriptHash = &self.transcript;

        Ok(self.handshake_keys = Some(HandshakeKeys::derive_handshake_keys(
            cipher_suite,
            psk,
            pbk,
            transcript)?
        ))
    }

    pub fn set_application_keys(&mut self) -> Result<(), Error> {
        let cipher_suite: &SupportedCipherSuite = self.cipher_suite.as_ref()
            .ok_or(Error::Crypto(format!("cipher suite is not set")))?;

        let mut psk: Option<&[u8]> = None;

        if let Some(k) = &self.pre_shared_key {
            psk = Some(&k.as_slice())
        };

        let pbk: &Bytes = self.peer_public_key.as_ref()
            .ok_or(Error::Crypto(format!("pbk is not set")))?;

        Ok(self.application_keys = Some(ApplicationKeys::derive_application_keys(
            cipher_suite,
            psk,
            pbk)?
        ))
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
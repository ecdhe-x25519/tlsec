use crate::certificate::cert_store::CertStore;
use crate::certificate::verify::{verify_certs, verify_certs_server};
use crate::encryption::key_schedule::HandshakeKeys;
use crate::message::alert::AlertDescription;
use crate::message::handshake::certificate::certificate::{CertificateEntryPayload, CertificatePayload};
use crate::message::handshake::certificate::certificate_verify::CertificateVerifyPayload;
use crate::message::handshake::hello::cipher_suite::SupportedCipherSuite;
use crate::message::handshake::hello::client::ClientHelloPayload;
use crate::message::handshake::message::client::ClientHandshakePayload;
use crate::message::handshake::messages::{CommonHandshakePayload, FinishedPayload, HandshakeMessage, HandshakePayload};
use crate::net::negotiation::server::extension::handle_extensions_server;
use crate::net::negotiation::server::handshake::{select_cipher_suites_server, select_compression_method_server};
use crate::net::state_machine::configs::ClientAuthMode;
use crate::net::state_machine::context::Context;
use crate::net::state_machine::side::ServerSide;
use crate::net::state_machine::state::{NextState, State};

use crate::error::TlsError;

pub struct ServerStart;

impl State<ServerSide> for ServerStart {
    fn handle(
        self: Box<Self>,
        _ctx: &mut Context<ServerSide>,
        _msg: HandshakeMessage,
    ) -> Result<NextState<ServerSide>, TlsError>
    {
        Ok(NextState::new(ExpectClientHello, None))
    }
}

pub struct ExpectClientHello;

impl State<ServerSide> for ExpectClientHello {
    fn handle(
        self: Box<Self>,
        ctx: &mut Context<ServerSide>,
        msg: HandshakeMessage,
    ) -> Result<NextState<ServerSide>, TlsError>
    {
        let client_hello: ClientHelloPayload = match msg.payload {
            HandshakePayload::Client(ClientHandshakePayload::ClientHello(ch)) => ch,
            _ => return Err(TlsError::Alert(AlertDescription::UnexpectedMessage)),
        };

        select_cipher_suites_server(ctx, &client_hello)?;

        select_compression_method_server(ctx, &client_hello)?;

        handle_extensions_server(ctx, &client_hello.extensions)?;

        ctx.common.transcript.update(&msg.raw);

        let cs: &SupportedCipherSuite = &ctx.common.cipher_suite
            .ok_or(TlsError::Alert(AlertDescription::HandshakeFailure))?;

        let psk: &Vec<u8> = ctx.common.pre_shared_key.as_ref()
            .ok_or(TlsError::Alert(AlertDescription::HandshakeFailure))?;

        let shared_key: &Vec<u8> = ctx.common.shared_key.as_ref()
            .ok_or(TlsError::Alert(AlertDescription::HandshakeFailure))?;

        let hs_keys: HandshakeKeys = HandshakeKeys::derive_handshake_keys(
            &cs,
            Some(&psk.as_ref()),
            &shared_key.as_ref(),
            &ctx.common.transcript
        )?;

        ctx.common.record_layer.prepare_decrypter(hs_keys.server);

        ctx.common.record_layer.start_decrypting();

        match ctx.config.client_auth_mode {
            ClientAuthMode::None => Ok(NextState::new(ExpectClientFinished, None)),
            ClientAuthMode::Require => Ok(NextState::new(ExpectClientCertificate, None)),
        }
    }
}

pub struct ExpectClientCertificate;

impl State<ServerSide> for ExpectClientCertificate {
    fn handle(
        self: Box<Self>,
        ctx: &mut Context<ServerSide>,
        msg: HandshakeMessage,
    ) -> Result<NextState<ServerSide>, TlsError>
    {
        let client_certificate: CertificatePayload = match msg.payload {
            HandshakePayload::Client(ClientHandshakePayload::Certificate(ch)) => ch,
            _ => return Err(TlsError::Alert(AlertDescription::UnexpectedMessage)),
        };

        let cert_store: &&CertStore = &ctx.config.common.cert_root.as_ref()
            .ok_or(TlsError::Alert(AlertDescription::CertificateUnknown))?;

        verify_certs_server(
            cert_store,
            &client_certificate.certificate_list,
            ctx.config.common.supported_signature_schemes.as_slice()
        )?;

        ctx.common.transcript.update(&msg.raw);

        Ok(NextState::new(ExpectClientCertificateVerify {certificate: client_certificate.certificate_list}, None))
    }
}

pub struct ExpectClientCertificateVerify {
    pub certificate: Vec<CertificateEntryPayload>,
}

impl State<ServerSide> for ExpectClientCertificateVerify {
    fn handle(
        self: Box<Self>,
        ctx: &mut Context<ServerSide>,
        msg: HandshakeMessage,
    ) -> Result<NextState<ServerSide>, TlsError>
    {
        let client_certificate_verify: CertificateVerifyPayload = match msg.payload {
            HandshakePayload::Client(ClientHandshakePayload::CertificateVerify(ch)) => ch,
            _ => return Err(TlsError::Alert(AlertDescription::UnexpectedMessage)),
        };

        verify_certs(
            &self.certificate,
            &client_certificate_verify,
            &ctx.common.transcript.hash(),
            &ctx.common.signature_scheme.ok_or(TlsError::Alert(AlertDescription::HandshakeFailure))?
        )?;

        ctx.common.transcript.update(&msg.raw);

        Ok(NextState::new(ExpectClientFinished, None))
    }
}

pub struct ExpectClientFinished;

impl State<ServerSide> for ExpectClientFinished {
    fn handle(
        self: Box<Self>,
        ctx: &mut Context<ServerSide>,
        msg: HandshakeMessage,
    ) -> Result<NextState<ServerSide>, TlsError>
    {
        let client_finished: FinishedPayload = match msg.payload {
            HandshakePayload::Common(CommonHandshakePayload::Finished(ch)) => ch,
            _ => return Err(TlsError::Alert(AlertDescription::UnexpectedMessage)),
        };

        ctx.common.transcript.update(&msg.raw);

        if client_finished.verify_data.as_ref() == ctx.common.transcript.hash() {
            return Ok(NextState::new(ServerConnected, None))
        }

        Err(TlsError::Alert(AlertDescription::HandshakeFailure))
    }
}

pub struct ServerConnected;

impl State<ServerSide> for ServerConnected {
    fn handle(
        self: Box<Self>,
        _ctx: &mut Context<ServerSide>,
        _msg: HandshakeMessage,
    ) -> Result<NextState<ServerSide>, TlsError>
    {
        Err(TlsError::Alert(AlertDescription::UnexpectedMessage))
    }
}
use crate::certificate::cert_store::CertStore;
use crate::certificate::verify::{verify_certs, verify_certs_client};
use crate::encryption::key_schedule::HandshakeKeys;
use crate::message::alert::AlertDescription;
use crate::message::handshake::certificate::certificate::{CertificateEntryPayload, CertificatePayload};
use crate::message::handshake::certificate::certificate_verify::CertificateVerifyPayload;
use crate::message::handshake::encrypted_extensions::EncryptedExtensionsPayload;
use crate::message::handshake::hello::cipher_suite::SupportedCipherSuite;
use crate::message::handshake::hello::server::ServerHelloPayload;
use crate::message::handshake::message::server::ServerHandshakePayload;
use crate::message::handshake::messages::{CommonHandshakePayload, FinishedPayload, HandshakeMessage, HandshakePayload};
use crate::net::negotiation::client::extension::handle_extensions_client;
use crate::net::negotiation::client::handshake::{select_cipher_suite_client, select_compression_method_client};
use crate::net::state_machine::context::Context;
use crate::net::state_machine::side::ClientSide;
use crate::net::state_machine::state::{NextState, State};

use crate::error::Error;

pub struct ClientStart;

impl State<ClientSide> for ClientStart {
    fn handle(
        self: Box<Self>,
        _ctx: &mut Context<ClientSide>,
        _msg: HandshakeMessage,
    ) -> Result<NextState<ClientSide>, Error>
    {
        Ok(NextState::new(ExpectServerHello, None))
    }
}

pub struct ExpectServerHello;

impl State<ClientSide> for ExpectServerHello {
    fn handle(
        self: Box<Self>,
        ctx: &mut Context<ClientSide>,
        msg: HandshakeMessage,
    ) -> Result<NextState<ClientSide>, Error>
    {
        let server_hello: ServerHelloPayload = match msg.payload {
            HandshakePayload::Server(ServerHandshakePayload::ServerHello(ch)) => ch,
            _ => return Err(Error::Alert(AlertDescription::UnexpectedMessage)),
        };

        select_cipher_suite_client(ctx, &server_hello)?;

        select_compression_method_client(ctx, &server_hello)?;

        handle_extensions_client(ctx, &server_hello.extensions)?;

        ctx.common.transcript.update(&msg.raw);

        let cs: &SupportedCipherSuite = &ctx.common.cipher_suite
            .ok_or(Error::Alert(AlertDescription::HandshakeFailure))?;

        let psk: &Vec<u8> = ctx.common.pre_shared_key.as_ref()
            .ok_or(Error::Alert(AlertDescription::HandshakeFailure))?;

        let shared_key: &Vec<u8> = ctx.common.shared_key.as_ref()
            .ok_or(Error::Alert(AlertDescription::HandshakeFailure))?;

        let hs_keys: HandshakeKeys = HandshakeKeys::derive_handshake_keys(
            &cs,
            Some(&psk.as_ref()),
            &shared_key.as_ref(),
            &ctx.common.transcript
        )?;

        ctx.common.record_layer.prepare_decrypter(hs_keys.server);

        ctx.common.record_layer.start_decrypting();

        Ok(NextState::new(ExpectEncryptedExtensions, None))
    }
}

pub struct ExpectEncryptedExtensions;

impl State<ClientSide> for ExpectEncryptedExtensions {
    fn handle(
        self: Box<Self>,
        ctx: &mut Context<ClientSide>,
        msg: HandshakeMessage,
    ) -> Result<NextState<ClientSide>, Error>
    {
        let server_ee: EncryptedExtensionsPayload = match msg.payload {
            HandshakePayload::Server(ServerHandshakePayload::EncryptedExtensions(ch)) => ch,
            _ => return Err(Error::Alert(AlertDescription::UnexpectedMessage)),
        };

        handle_extensions_client(ctx, &server_ee.extensions)?;

        ctx.common.transcript.update(&msg.raw);

        Ok(NextState::new(ExpectCertificate, None))
    }
}

pub struct ExpectCertificate;

impl State<ClientSide> for ExpectCertificate {
    fn handle(
        self: Box<Self>,
        ctx: &mut Context<ClientSide>,
        msg: HandshakeMessage,
    ) -> Result<NextState<ClientSide>, Error>
    {
        let server_certificate: CertificatePayload = match msg.payload {
            HandshakePayload::Server(ServerHandshakePayload::Certificate(ch)) => ch,
            _ => return Err(Error::Alert(AlertDescription::UnexpectedMessage)),
        };

        let cert_store: &&CertStore = &ctx.config.common.cert_root.as_ref()
            .ok_or(Error::Alert(AlertDescription::CertificateUnknown))?;

        let server_name: &&String = &ctx.config.common.server_name.as_ref()
            .ok_or(Error::Alert(AlertDescription::BadCertificate))?;

        verify_certs_client(
            cert_store,
            &server_certificate.certificate_list,
            ctx.config.common.supported_signature_schemes.as_slice(),
            &ctx.config.verify_dns,
            Some(server_name.as_ref()),
        )?;

        ctx.common.transcript.update(&msg.raw);

        Ok(NextState::new(ExpectCertificateVerify {certificate: server_certificate.certificate_list}, None))
    }
}

pub struct ExpectCertificateVerify {
    pub certificate: Vec<CertificateEntryPayload>,
}

impl State<ClientSide> for ExpectCertificateVerify {
    fn handle(
        self: Box<Self>,
        ctx: &mut Context<ClientSide>,
        msg: HandshakeMessage,
    ) -> Result<NextState<ClientSide>, Error>
    {
        let server_certificate_verify: CertificateVerifyPayload = match msg.payload {
            HandshakePayload::Server(ServerHandshakePayload::CertificateVerify(ch)) => ch,
            _ => return Err(Error::Alert(AlertDescription::UnexpectedMessage)),
        };

        verify_certs(
            &self.certificate,
            &server_certificate_verify,
            &ctx.common.transcript.hash(),
            &ctx.common.signature_scheme.ok_or(Error::Alert(AlertDescription::HandshakeFailure))?
        )?;

        ctx.common.transcript.update(&msg.raw);

        Ok(NextState::new(ExpectServerFinished, None))
    }
}

pub struct ExpectServerFinished;

impl State<ClientSide> for ExpectServerFinished {
    fn handle(
        self: Box<Self>,
        ctx: &mut Context<ClientSide>,
        msg: HandshakeMessage,
    ) -> Result<NextState<ClientSide>, Error>
    {
        let server_finished: FinishedPayload = match msg.payload {
            HandshakePayload::Common(CommonHandshakePayload::Finished(ch)) => ch,
            _ => return Err(Error::Alert(AlertDescription::UnexpectedMessage)),
        };

        ctx.common.transcript.update(&msg.raw);

        if server_finished.verify_data.as_ref() == ctx.common.transcript.hash() {
            return Ok(NextState::new(ClientConnected, None))
        }

        Err(Error::Alert(AlertDescription::HandshakeFailure))
    }
}

pub struct ClientConnected;

impl State<ClientSide> for ClientConnected {
    fn handle(
        self: Box<Self>,
        _ctx: &mut Context<ClientSide>,
        _msg: HandshakeMessage,
    ) -> Result<NextState<ClientSide>, Error>
    {
        Err(Error::Alert(AlertDescription::UnexpectedMessage))
    }
}
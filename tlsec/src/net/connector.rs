use super::negotiation::*;

use crate::message::*;

use crate::certificate::*;

use super::state_machine::*;

use crate::error::*;

pub struct ClientStart;

impl State<ClientSide> for ClientStart {
    fn handle(
        self: Box<Self>,
        _ctx: &mut Context<ClientSide>,
        _msg: HandshakeMessage,
    ) -> Result<NextState<ClientSide>, Error>
    {
        
        Ok(NextState::new(ExpectServerHello { client_hello: _ctx.config.client_hello }, None))
    }
}

pub struct ExpectServerHello {
    pub client_hello: ClientHelloPayload,
}

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

        match select_cipher_suite_client(ctx, &server_hello) {
            Ok(()) => Ok(()),
            Err(e) => {
                return Err(e)
            }
        };

        match select_compression_method_client(ctx, &server_hello) {
            Ok(()) => Ok(()),
            Err(e) => {
                return Err(e)
            }
        };

        match handle_extensions_client(ctx, &server_hello.extensions) {
            Ok(()) => Ok(()),
            Err(e) => {
                return Err(e)
            }
        };

        ctx.update_transcript(&msg.encode(buf));

        Ok(NextState::new(ExpectEncryptedExtensions, server_hello))
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

        handle_extensions_client(&mut ctx, &server_ee.extensions)?;
        
        ctx.update_transcript(&msg.encode(buf));

        Ok(NextState::new(ExpectCertificate, server_ee))
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

        parse_certs_client(
            ctx,
            &client_certificate,
            ctx.config.common.supported_signature_schemes.as_slice(),
            &ctx.config.verify_dns,
            ctx.config.server_name.as_ref(),
        )?;

        ctx.update_transcript(&msg.encode(buf));

        Ok(NextState::new(ExpectCertificateVerify, server_certificate))
    }
}

pub struct ExpectCertificateVerify;

impl State<ClientSide> for ExpectCertificateVerify {
    fn handle(
        self: Box<Self>,
        ctx: &mut Context<ClientSide>,
        msg: HandshakeMessage,
    ) -> Result<NextState<ClientSide>, Error>
    {
        let server_certificate: CertificatePayload = match msg.payload {
            HandshakePayload::Client(ClientHandshakePayload::Certificate(ch)) => ch,
            _ => return Err(Error::Alert(AlertDescription::UnexpectedMessage)),
        };

        let server_certificate_verify: CertificateVerifyPayload = match msg.payload {
            HandshakePayload::Server(ServerHandshakePayload::CertificateVerify(ch)) => ch,
            _ => return Err(Error::Alert(AlertDescription::UnexpectedMessage)),
        };

        verify_certs(
            &server_certificate,
            &server_certificate_verify,
            &ctx.common.transcript.hash(),
            &ctx.common.signature_scheme.ok_or(Error::Alert(AlertDescription::HandshakeFailure))?
        )?;

        ctx.update_transcript(&msg.encode(buf));

        Ok(NextState::new(ExpectServerFinished, server_certificate_verify))
    }
}

pub struct ExpectServerFinished {
    pub handshake_keys: HandshakeKeys,
}

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

        if server_finished.verify_data.as_ref() == ctx.common.transcript.hash() {
            return Ok(NextState::new(ClientConnected, server_finished))
        }

        Err(Error::Alert(AlertDescription::HandshakeFailure))
    }
}

pub struct ClientConnected;

impl State<ClientSide> for ClientConnected {
    fn handle(
        self: Box<Self>,
        ctx: &mut Context<ClientSide>,
        msg: HandshakeMessage,
    ) -> Result<NextState<ClientSide>, Error>
    {
        Ok(())
    }
}
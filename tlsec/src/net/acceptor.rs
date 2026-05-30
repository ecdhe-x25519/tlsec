use super::negotiation::*;

use crate::message::*;

use crate::certificate::*;

use super::state_machine::*;

use crate::error::*;

pub struct ServerStart;

impl State<ServerSide> for ServerStart {
    fn handle(
        self: Box<Self>,
        _ctx: &mut Context<ServerSide>,
        _msg: HandshakeMessage,
    ) -> Result<NextState<ServerSide>, Error>
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
    ) -> Result<NextState<ServerSide>, Error>
    {
        let client_hello: ClientHelloPayload = match msg.payload {
            HandshakePayload::Client(ClientHandshakePayload::ClientHello(ch)) => ch,
            _ => return Err(Error::Alert(AlertDescription::UnexpectedMessage)),
        };

        match select_cipher_suites_server(ctx, &client_hello) {
            Ok(()) => Ok(()),
            Err(e) => {
                return Err(e)
            }
        };

        match select_compression_method_server(ctx, &client_hello) {
            Ok(()) => Ok(()),
            Err(e) => {
                return Err(e)
            }
        };

        match handle_extensions_server(ctx, &client_hello.extensions) {
            Ok(()) => Ok(()),
            Err(e) => {
                return Err(e)
            }
        };

        ctx.update_transcript(&msg.encode(buf));

        let server_hello: ServerHelloPayload = ctx.config.server_hello;

        match ctx.config.client_auth_mode {
            ClientAuthMode::None => Ok(NextState::new(ExpectClientFinished { handshake_keys }, &client_hello)),
            ClientAuthMode::Require => Ok(NextState::new(ExpectClientCertificate, &client_hello)),
        }
    }
}

pub struct ExpectClientCertificate;

impl State<ServerSide> for ExpectClientCertificate {
    fn handle(
        self: Box<Self>,
        ctx: &mut Context<ServerSide>,
        msg: HandshakeMessage,
    ) -> Result<NextState<ServerSide>, Error>
    {
        let client_certificate: CertificatePayload = match msg.payload {
            HandshakePayload::Client(ClientHandshakePayload::Certificate(ch)) => ch,
            _ => return Err(Error::Alert(AlertDescription::UnexpectedMessage)),
        };

        parse_certs_server(
            ctx,
            &client_certificate,
            ctx.config.common.supported_signature_schemes.as_slice()
        )?;

        ctx.update_transcript(&msg.encode(buf));

        Ok(NextState::new(ExpectClientCertificateVerify, client_certificate))
    }
}

pub struct ExpectClientCertificateVerify;

impl State<ServerSide> for ExpectClientCertificateVerify {
    fn handle(
        self: Box<Self>,
        ctx: &mut Context<ServerSide>,
        msg: HandshakeMessage,
    ) -> Result<NextState<ServerSide>, Error>
    {
        let client_certificate: CertificatePayload = match msg.payload {
            HandshakePayload::Client(ClientHandshakePayload::Certificate(ch)) => ch,
            _ => return Err(Error::Alert(AlertDescription::UnexpectedMessage)),
        };

        let client_certificate_verify: CertificateVerifyPayload = match msg.payload {
            HandshakePayload::Client(ClientHandshakePayload::CertificateVerify(ch)) => ch,
            _ => return Err(Error::Alert(AlertDescription::UnexpectedMessage)),
        };

        verify_certs(
            &client_certificate,
            &client_certificate_verify,
            &ctx.common.transcript.hash(),
            &ctx.common.signature_scheme.ok_or(Error::Alert(AlertDescription::HandshakeFailure))?
        )?;

        ctx.update_transcript(&msg.encode(buf));

        Ok(NextState::new(ExpectClientFinished, client_certificate_verify))
    }
}

pub struct ExpectClientFinished {
    pub handshake_keys: HandshakeKeys,
}

impl State<ServerSide> for ExpectClientFinished {
    fn handle(
        self: Box<Self>,
        ctx: &mut Context<ServerSide>,
        msg: HandshakeMessage,
    ) -> Result<NextState<ServerSide>, Error>
    {
        let client_finished: FinishedPayload = match msg.payload {
            HandshakePayload::Common(CommonHandshakePayload::Finished(ch)) => ch,
            _ => return Err(Error::Alert(AlertDescription::UnexpectedMessage)),
        };

        if client_finished.verify_data.as_ref() == ctx.common.transcript.hash() {
            return Ok(NextState::new(ServerConnected, client_finished))
        }

        Err(Error::Alert(AlertDescription::HandshakeFailure))
    }
}

pub struct ServerConnected;

impl State<ServerSide> for ServerConnected {
    fn handle(
        self: Box<Self>,
        ctx: &mut Context<ServerSide>,
        msg: crate::message::handshake::handshake::HandshakeMessage,
    ) -> Result<NextState<ServerSide>, Error>
    {
        Ok(())
    }
}
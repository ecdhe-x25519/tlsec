use super::negotiation::server::extension::handle_extensions_server;
use super::negotiation::server::handshake::{select_cipher_suites_server, select_compression_method_server};

use crate::messages::handshake::handshake::HandshakeMessage;

use crate::messages::handshake::handshake::certificate::{CertificatePayload, CertificateVerifyPayload};
use crate::messages::handshake::handshake::client::*;
use crate::messages::handshake::handshake::*;

use crate::net::state_machine::configs::ClientAuthMode;
use crate::net::state_machine::context::Context;
use crate::net::state_machine::state::NextState;

use super::state_machine::state::State;
use super::state_machine::ServerSide;

use crate::error::Error;

use crate::messages::record::AlertDescription;

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

        match ctx.config.client_auth_mode {
            ClientAuthMode::None => Ok(NextState::new(ExpectClientFinished { handshake_keys }, &client_hello)),
            ClientAuthMode::Request => Ok(NextState::new(ExpectClientCertificate, &client_hello)),
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

        ctx.update_transcript(&msg.encode(buf));
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
        let client_certificate: CertificateVerifyPayload = match msg.payload {
            HandshakePayload::Client(ClientHandshakePayload::CertificateVerify(ch)) => ch,
            _ => return Err(Error::Alert(AlertDescription::UnexpectedMessage)),
        };

        ctx.update_transcript(&msg.encode(buf));
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
        let client_certificate: FinishedPayload = match msg.payload {
            HandshakePayload::Common(CommonHandshakePayload::Finished(ch)) => ch,
            _ => return Err(Error::Alert(AlertDescription::UnexpectedMessage)),
        };

        ctx.update_transcript(&msg.encode(buf));
    }
}

pub struct ServerConnected;

impl State<ServerSide> for ServerConnected {
    fn handle(
        self: Box<Self>,
        ctx: &mut Context<ServerSide>,
        msg: crate::messages::handshake::handshake::HandshakeMessage,
    ) -> Result<NextState<ServerSide>, Error>
    {
        
    }
}
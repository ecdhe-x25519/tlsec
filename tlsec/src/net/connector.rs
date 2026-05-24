use super::negotiation::client::extension::handle_extensions_client;
use super::negotiation::client::handshake::{select_cipher_suite_client, select_compression_method_client};

use crate::messages::handshake::handshake::HandshakeMessage;

use crate::messages::handshake::handshake::certificate::{CertificatePayload, CertificateVerifyPayload};
use crate::messages::handshake::handshake::client::ClientHelloPayload;
use crate::messages::handshake::handshake::server::{EncryptedExtensionsPayload, ServerHandshakePayload, ServerHelloPayload};
use crate::messages::handshake::handshake::*;

use super::state_machine::state::State;
use super::state_machine::ClientSide;

use crate::net::state_machine::context::Context;
use crate::net::state_machine::state::NextState;

use crate::error::Error;

use crate::messages::record::AlertDescription;

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
        let client_certificate: EncryptedExtensionsPayload = match msg.payload {
            HandshakePayload::Server(ServerHandshakePayload::EncryptedExtensions(ch)) => ch,
            _ => return Err(Error::Alert(AlertDescription::UnexpectedMessage)),
        };

        ctx.update_transcript(&msg.encode(buf));
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
        let client_certificate: CertificatePayload = match msg.payload {
            HandshakePayload::Server(ServerHandshakePayload::Certificate(ch)) => ch,
            _ => return Err(Error::Alert(AlertDescription::UnexpectedMessage)),
        };

        ctx.update_transcript(&msg.encode(buf));
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
        let certificate_verify: CertificateVerifyPayload = match msg.payload {
            HandshakePayload::Server(ServerHandshakePayload::CertificateVerify(ch)) => ch,
            _ => return Err(Error::Alert(AlertDescription::UnexpectedMessage)),
        };

        ctx.update_transcript(&msg.encode(buf));
    }
}

pub struct ExpectFinished {
    pub handshake_keys: HandshakeKeys,
}

impl State<ClientSide> for ExpectFinished {
    fn handle(
        self: Box<Self>,
        ctx: &mut Context<ClientSide>,
        msg: HandshakeMessage,
    ) -> Result<NextState<ClientSide>, Error>
    {
        let server_certificate: FinishedPayload = match msg.payload {
            HandshakePayload::Common(CommonHandshakePayload::Finished(ch)) => ch,
            _ => return Err(Error::Alert(AlertDescription::UnexpectedMessage)),
        };

        ctx.update_transcript(&msg.encode(buf));
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
        
    }
}
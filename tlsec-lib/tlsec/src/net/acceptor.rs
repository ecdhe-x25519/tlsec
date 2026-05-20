use super::negotiation::handshake::*;
use super::negotiation::client::*;
use super::negotiation::server::*;

use crate::messages::Serialize;
use crate::messages::handshake::*;
use crate::messages::handshake::handshake::*;
use crate::messages::handshake::extensions::*;
use crate::messages::Version::Tls12;
use crate::messages::handshake::CompressionMethod::Null;

use crate::encryption::supported_suites::*;
use crate::encryption::Random;

use crate::net::state_machine::context::Context;
use crate::net::state_machine::state::NextState;

use super::state_machine::state::State;
use super::state_machine::ServerSide;
use super::state_machine::*;

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
        let client_hello = match msg.payload {
            HandshakePayload::ClientHello(ch) => ch,
            _ => return Err(Error::UnexpectedMessage)
        };

        let cipher_suite: SupportedCipherSuite = select_cipher_suite(
            &client_hello.cipher_suites,
            &ctx.config.common.cipher_suites
        )?;

        

        ctx.set_cipher_suite(cipher_suite);

        ctx.update_transcript(&msg.encode(buf));

        let cipher_suite = ctx.set_cipher_suite(cipher_suite);




        let mut random = [0u8; 32];
        let rng = Random::new()?;
        rng.secure_random(&mut random)?;

        let exts = Extension {

        };

        let server_hello = ServerHelloPayload {
            legacy_version: Tls12,
            random,
            legacy_session_id_echo: client_hello.legacy_session_id,
            cipher_suite: cipher_suite,
            legacy_compression_method: Null,
            extensions: exts,
        }.encode(buf);

        if ctx.config.client_auth {
            Ok(NextState::new(ExpectClientCertificate, server_hello))
        } else {
            Ok(NextState::new(ExpectClientFinished, server_hello))
        };


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
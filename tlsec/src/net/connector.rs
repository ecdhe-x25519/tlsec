use crate::encryption::cipher_suite::HandshakeKeys;
use crate::messages::handshake::handshake::{HandshakeMessage};

use super::state_machine::state::State;
use super::state_machine::ClientSide;

use crate::net::state_machine::context::Context;
use crate::net::state_machine::state::NextState;

use super::state_machine::*;

pub struct ClientStart;

impl State<ClientSide> for ClientStart {
    fn handle(
        self: Box<Self>,
        ctx: &mut Context<ClientSide>,
        msg: HandshakeMessage,
    ) -> Result<NextState<ClientSide>, Error>
    {
        Ok(NextState::new(ExpectServerHello, None))
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
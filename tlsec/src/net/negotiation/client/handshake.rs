use crate::messages::handshake::handshake::server::ServerHelloPayload;
use crate::messages::record::AlertDescription;

use crate::net::state_machine::ClientSide;
use crate::net::state_machine::context::Context;

use crate::error::Error;

pub fn select_cipher_suite_client(
    ctx: &mut Context<ClientSide>,
    hello: &ServerHelloPayload
) -> Result<(), Error> {
    let cipher_suite = hello.cipher_suite;

    for cs in &ctx.config.common.supported_cipher_suites {
        if let Some(cs) = cs.compare(&cipher_suite) {
            ctx.common.cipher_suite = Some(cs);
            return Ok(())
        }
    }

    Err(Error::Alert(AlertDescription::HandshakeFailure))
}

pub fn select_compression_method_client(
    ctx: &mut Context<ClientSide>,
    hello: &ServerHelloPayload
) -> Result<(), Error> {
    for cm in &ctx.config.common.supported_compression_method {
        if let Some(cm) = cm.compare(&hello.legacy_compression_method) {
            ctx.common.compression_method = Some(cm);
            return Ok(())
        }
    }

    Err(Error::Alert(AlertDescription::HandshakeFailure))
}
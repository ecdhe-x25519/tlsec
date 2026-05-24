use crate::messages::handshake::handshake::client::ClientHelloPayload;
use crate::messages::record::AlertDescription;

use crate::net::state_machine::ServerSide;
use crate::net::state_machine::context::Context;

use crate::error::Error;

pub fn select_cipher_suites_server(
    ctx: &mut Context<ServerSide>,
    hello: &ClientHelloPayload
) -> Result<(), Error> {
    for cs in &ctx.config.common.supported_cipher_suites {
        for cipher_suite in &hello.cipher_suites {
            if let Some(cs) = cs.compare(&cipher_suite) {
                ctx.common.cipher_suite = Some(cs);
                return Ok(())
            }
        }
    }

    Err(Error::Alert(AlertDescription::HandshakeFailure))
}

pub fn select_compression_method_server(
    ctx: &mut Context<ServerSide>,
    hello: &ClientHelloPayload
) -> Result<(), Error> {
    for cm in &ctx.config.common.supported_compression_method {
        for compression_method in &hello.legacy_compression_methods {
            if let Some(cm) = cm.compare(&compression_method) {
                ctx.common.compression_method = Some(cm);
                return Ok(())
            }
        }
    }

    Err(Error::Alert(AlertDescription::HandshakeFailure))
}
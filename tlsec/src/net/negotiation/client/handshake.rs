use crate::message::alert::AlertDescription;
use crate::net::state_machine::side::ClientSide;
use crate::message::handshake::hello::server::ServerHelloPayload;
use crate::net::state_machine::context::Context;

use crate::error::TlsError;

pub fn select_cipher_suite_client(
    ctx: &mut Context<ClientSide>,
    hello: &ServerHelloPayload
) -> Result<(), TlsError> {
    let cipher_suite = hello.cipher_suite;

    for cs in &ctx.config.common.supported_cipher_suites {
        if let Some(cs) = cs.compare(&cipher_suite) {
            ctx.common.cipher_suite = Some(cs);
            return Ok(())
        }
    }

    Err(TlsError::Alert(AlertDescription::HandshakeFailure))
}

pub fn select_compression_method_client(
    ctx: &mut Context<ClientSide>,
    hello: &ServerHelloPayload
) -> Result<(), TlsError> {
    for cm in &ctx.config.common.supported_compression_method {
        if let Some(cm) = cm.compare(&hello.legacy_compression_method) {
            ctx.common.compression_method = Some(cm);
            return Ok(())
        }
    }

    Err(TlsError::Alert(AlertDescription::HandshakeFailure))
}
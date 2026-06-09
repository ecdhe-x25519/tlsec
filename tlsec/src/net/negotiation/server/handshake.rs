use crate::message::alert::AlertDescription;
use crate::net::state_machine::side::ServerSide;
use crate::message::handshake::hello::client::ClientHelloPayload;
use crate::net::state_machine::context::Context;

use crate::error::TlsError;

pub fn select_cipher_suites_server(
    ctx: &mut Context<ServerSide>,
    hello: &ClientHelloPayload
) -> Result<(), TlsError> {
    for cs in &ctx.config.common.supported_cipher_suites {
        for cipher_suite in &hello.cipher_suites {
            if let Some(cs) = cs.compare(&cipher_suite) {
                ctx.common.cipher_suite = Some(cs);
                return Ok(())
            }
        }
    }

    Err(TlsError::Alert(AlertDescription::HandshakeFailure))
}

pub fn select_compression_method_server(
    ctx: &mut Context<ServerSide>,
    hello: &ClientHelloPayload
) -> Result<(), TlsError> {
    for cm in &ctx.config.common.supported_compression_method {
        for compression_method in &hello.legacy_compression_methods {
            if let Some(cm) = cm.compare(&compression_method) {
                ctx.common.compression_method = Some(cm);
                return Ok(())
            }
        }
    }

    Err(TlsError::Alert(AlertDescription::HandshakeFailure))
}
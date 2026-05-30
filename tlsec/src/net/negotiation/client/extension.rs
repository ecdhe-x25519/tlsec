use crate::message::*;

use crate::net::state_machine::context::Context;
use crate::net::state_machine::ClientSide;

use crate::error::*;

use bytes::*;

pub fn handle_extensions_client(
    mut ctx: &mut Context<ClientSide>,
    exts: &[Extension]
) -> Result<(), Error> {
    let mut version: Option<SupportedVersion> = None;
    let mut alpn_protocol: Option<AlpnProtocols> = None;
    let mut named_group: Option<SupportedNamedGroup> = None;
    let mut pbk: Option<Bytes> = None;
    let mut error: Option<Error> = None;

    for ext in exts {
        match &ext.payload {
            ExtensionPayload::Server(server_type) => {
                match server_type {
                    ServerExtensionPayload::ALPN(p) => {
                        match handle_alpn(p, &mut ctx) {
                            Ok(alpn) => alpn_protocol = Some(alpn),
                            Err(e) => {
                                error = Some(e);
                                break;
                            }
                        }
                    }
                    ServerExtensionPayload::SupportedVersionsServer(p) => {
                        match handle_supported_versions(p, &mut ctx) {
                            Ok(sv) => version = Some(sv),
                            Err(e) => {
                                error = Some(e);
                                break;
                            }
                        }
                    }
                    ServerExtensionPayload::KeyShareServer(p) => {
                        match handle_key_share(p, &mut ctx) {
                            Ok(key) => pbk = Some(key),
                            Err(e) => {
                                error = Some(e);
                                break;
                            }
                        }
                    }
                    ServerExtensionPayload::KeyShareHelloRetryRequest(p) => {
                        match handle_key_share_hello_retry_request(p, &mut ctx) {
                            Ok(ng) => named_group = Some(ng),
                            Err(e) => {
                                error = Some(e);
                                break;
                            }
                        }
                    }
                    _ => continue,
                }
            }
            _ => return Err(Error::Alert(AlertDescription::UnexpectedMessage))
        };
    }

    if let Some(e) = error {
        return Err(e);
    };

    ctx.common.alpn_protocol = alpn_protocol;
    ctx.common.named_group = named_group;
    ctx.common.version = version;
    ctx.common.peer_public_key = pbk;

    Ok(())
}

fn handle_supported_versions(
    ext: &SupportedVersionsServer,
    ctx: &mut Context<ClientSide>
) -> Result<SupportedVersion, Error> {
    for supported in &ctx.config.common.supported_versions {
        if let Some(v) = supported.compare(&ext.selected_version) {
            return Ok(v);
        }
    }
    
    Err(Error::Alert(AlertDescription::ProtocolVersion))
}

fn handle_alpn(
    ext: &AlpnPayload,
    ctx: &mut Context<ClientSide>
) -> Result<AlpnProtocols, Error> {
    let protocol: &AlpnProtocols = ctx.common.alpn_protocol.as_ref().ok_or(Error::Alert(AlertDescription::NoApplicationProtocol))?;

    for e in &ext.protocols {
        if &e.name == protocol {
            return Ok(e.name)
        }
    };

    Err(Error::Alert(AlertDescription::UnsupportedExtension))
}

fn handle_key_share(
    ext: &KeyShareServer,
    ctx: &mut Context<ClientSide>
) -> Result<Bytes, Error> {
    for supported in &ctx.config.common.supported_named_groups {
        if let Some(_) = supported.compare(&ext.server_share.group) {
            return Ok(ext.server_share.key_exchange.to_owned())
        }
    }

    Err(Error::Alert(AlertDescription::HandshakeFailure))
}

fn handle_key_share_hello_retry_request(
    ext: &KeyShareHelloRetryRequest,
    ctx: &mut Context<ClientSide>
) -> Result<SupportedNamedGroup, Error> {
    for supported in &ctx.config.common.supported_named_groups {
        if let Some(ng) = supported.compare(&ext.selected_group) {
            return Ok(ng)
        }
    }

    Err(Error::Alert(AlertDescription::IllegalParameter))
}
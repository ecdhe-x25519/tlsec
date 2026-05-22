use crate::messages::handshake::extensions::{*, server::*};

use crate::net::state_machine::context::Context;
use crate::net::state_machine::ClientSide;

use crate::error::Error;

pub fn parse_extensions_client(ctx: &Context<ClientSide>, exts: &[Extension]) -> Result<(), Error> {
    for ext in exts {
        match &ext.data {
            ExtensionPayload::Server(server_type) => {
                match server_type {
                    ServerExtensionPayload::ALPN(p) => handle_alpn(p, ctx)?,
                    ServerExtensionPayload::SupportedVersionsServer(p) => handle_supported_versions(p, ctx)?,
                    ServerExtensionPayload::KeyShareServer(p) => handle_key_share(p, ctx)?,
                    ServerExtensionPayload::RenegotiationInfo => continue,
                    ServerExtensionPayload::KeyShareHelloRetryRequest(p) => handle_key_share_hello_retry_request(p, ctx)?,
                }
            }
            _ => return Err(Error::UnsupportedExtension)
        };
    }

    Ok(())
}

fn handle_supported_versions(ext: &SupportedVersionsServer, ctx: &Context<ClientSide>) -> Result<(), Error> {
    for supported in &ctx.config.common.supported_versions {
        if let Some(_) = supported.compare(&ext.selected_version) {
            return Ok(());
        }
    }
    
    Err(Error::UnsupportedVersion)
}

fn handle_alpn(ext: &AlpnPayload, ctx: &Context<ClientSide>) -> Result<(), Error> {
    let protocol: &AlpnProtocols = ctx.common.alpn_protocol.as_ref().ok_or(Error::UnsupportedALPN)?;

    for e in &ext.protocols {
        if &e.name == protocol {
            return Ok(())
        }
    };

    Err(Error::UnsupportedALPN)
}

fn handle_key_share(ext: &KeyShareServer, ctx: &Context<ClientSide>) -> Result<(), Error> {
    for supported in &ctx.config.common.supported_named_groups {
        if let Some(_) = supported.compare(&ext.server_share.group) {
            return Ok(())
        }
    }

    Ok(())
}

fn handle_key_share_hello_retry_request(ext: &KeyShareHelloRetryRequest, ctx: &Context<ClientSide>) -> Result<(), Error> {
    Ok(())
}
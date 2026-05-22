use crate::messages::handshake::extensions::{*, server::*};

use crate::net::state_machine::context::Context;
use crate::net::state_machine::ClientSide;

use crate::error::Error;

use bytes::BytesMut;

pub fn parse_extensions_client(ctx: &Context<ClientSide>, exts: &[Extension]) -> Result<(), Error> {
    let mut server_name = None;
    let mut key_share = None;
    let mut supported_versions = None;
    let mut signature_algorithms = None;
    let mut supported_groups = None;
    let mut alpn = None;

    for ext in exts {
        match ext.data {
            ExtensionPayload::Server(server_type) => {
                match server_type {
                    ServerExtensionPayload::ALPN(p) => handle_alpn(p, ctx)?,
                    ServerExtensionPayload::SupportedVersionsServer(p) => handle_supported_versions_server(p, ctx)?,
                    ServerExtensionPayload::KeyShareServer(p) => handle_key_share_server(p, ctx)?,
                    ServerExtensionPayload::RenegotiationInfo => handle_renegotiation_info(ctx)?,
                    ServerExtensionPayload::KeyShareHelloRetryRequest(p) => handle_key_share_hello_retry_request(p, ctx)?,
                }
            }
            _ => return Err(Error::UnsupportedExtension)
        };
    }

    Ok(())
}

fn handle_supported_versions_server(ext: SupportedVersionsServer, ctx: &Context<ClientSide>) -> Result<(), Error> {
    if ext.selected_version == ctx.config.common.supported_cipher_suites { Ok(()) } else { Err(Error::UnsupportedVersion) }
}

fn handle_alpn(ext: AlpnPayload, ctx: &Context<ClientSide>) -> Result<(), Error> {
    let protocol: &AlpnProtocols = ctx.common.alpn_protocol.as_ref().ok_or(Error::UnsupportedALPN)?;

    for e in &ext.protocols {
        if &e.name == protocol {
            return Ok(())
        }
    };

    Err(Error::UnsupportedALPN)
}

fn handle_key_share_server(ext: KeyShareServer, ctx: &Context<ClientSide>) -> Result<BytesMut, Error> {
    if ext.server_share.group == ctx.config.common {};
    Ok(ext.server_share.key_exchange)
}

fn handle_renegotiation_info(ctx: &Context<ClientSide>) -> Result<(), Error> {
    
}

fn handle_key_share_hello_retry_request(ext: KeyShareHelloRetryRequest, ctx: &Context<ClientSide>) -> Result<(), Error> {
    
}
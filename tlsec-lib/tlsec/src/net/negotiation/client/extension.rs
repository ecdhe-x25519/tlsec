use crate::messages::handshake::extensions::{*, server::*};

use crate::net::state_machine::Side;
use crate::net::state_machine::context::Context;

use crate::error::Error;

pub fn parse_extensions_client<S: Side>(ctx: &Context<S>, exts: &[Extension]) -> Result<(), Error> {
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
                    ServerExtensionPayload::ALPN(p) => handle_alpn(p, ctx),
                    ServerExtensionPayload::SupportedVersionsServer(p) => handle_supported_versions_server(p, ctx),
                    ServerExtensionPayload::KeyShareServer(p) => handle_key_share_server(p, ctx),
                    ServerExtensionPayload::RenegotiationInfo => handle_renegotiation_info(ctx),
                    ServerExtensionPayload::KeyShareHelloRetryRequest(p) => handle_key_share_hello_retry_request(p, ctx),
                }
            }
            _ => return Err(Error::UnexpectedMessage)
        };
    }

    Ok(());
}

fn handle_supported_versions_server<S: Side>(ext: SupportedVersionsServer, ctx: &Context<S>) -> Result<(), Error> {
    if ext.selected_version == ctx { } else { }
}

fn handle_alpn<S: Side>(ext: AlpnPayload, ctx: &Context<S>) -> Result<(), Error> {
    if ext.protocols.contains(x) { } else { }
}

fn handle_key_share_server<S: Side>(ext: KeyShareServer, ctx: &Context<S>) -> Result<(), Error> {
    if ext.server_share.
}

fn handle_renegotiation_info<S: Side>(ctx: &Context<S>) -> Result<(), Error> {

}

fn handle_key_share_hello_retry_request<S: Side>(ext: KeyShareHelloRetryRequest, ctx: &Context<S>) -> Result<(), Error> {
    
}
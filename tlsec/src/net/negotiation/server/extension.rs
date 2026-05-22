use crate::messages::handshake::extensions::{*, client::*};

use crate::messages::handshake::handshake::server::NewSessionTicketPayload;
use crate::net::state_machine::ServerSide;
use crate::net::state_machine::context::Context;

use crate::error::Error;

pub fn parse_extensions_server(ctx: &Context<ServerSide>, exts: &[Extension]) -> Result<(), Error> {
    let mut server_name = None;
    let mut key_share = None;
    let mut supported_versions = None;
    let mut signature_algorithms = None;
    let mut supported_groups = None;
    let mut alpn = None;

    for ext in exts {
        match ext.data {
            ExtensionPayload::Client(client_type) => {
                match client_type {
                    ClientExtensionPayload::ServerName(p) => handle_server_name(p, ctx)?,
                    ClientExtensionPayload::StatusRequest(p) => handle_status_request(p, ctx)?,
                    ClientExtensionPayload::SupportedGroups(p) => handle_supported_groups(p, ctx)?,
                    ClientExtensionPayload::EcPointFormats(p) => handle_ec_point_formats(p, ctx)?,
                    ClientExtensionPayload::SignatureAlgorithms(p) => handle_signature_algorithms(p, ctx)?,
                    ClientExtensionPayload::ALPN(p) => handle_alpn(p, ctx)?,
                    ClientExtensionPayload::SignedCertificateTimestamp => handle_sct(p, ctx)?,
                    ClientExtensionPayload::ExtendedMainSecret => handle_extended_main_secret(p, ctx)?,
                    ClientExtensionPayload::CompressCertificate(p) => handle_compress_certificate(p, ctx)?,
                    ClientExtensionPayload::SessionTicket => handle_session_ticket(p, ctx)?,
                    ClientExtensionPayload::SupportedVersionsClient(p) => handle_supported_versions_client(p, ctx)?,
                    ClientExtensionPayload::PSKKeyExchangeModes(p) => handle_psk_key_exchange_modes(p, ctx)?,
                    ClientExtensionPayload::KeyShareClient(p) => handle_key_share_client(p, ctx)?,
                    ClientExtensionPayload::ApplicationSettings(p) => handle_application_settings(p, ctx)?,
                    ClientExtensionPayload::EncryptedClientHello(p) => handle_encrypted_client_hello(p, ctx)?,
                    ClientExtensionPayload::Grease(p) => continue,
                }
            }
            _ => return Err(Error::UnsupportedExtension)
        };
    }

    Ok(())
}

fn handle_supported_versions_client(ext: SupportedVersionsClient, ctx: &Context<ServerSide>) -> Result<(), Error> {
    if ext.versions.contains(&ctx.config.common.supported_version) { Ok(()) } else { Err(Error::UnsupportedVersion) }
}

fn handle_supported_groups(ext: SupportedGroupsPayload, ctx: &Context<ServerSide>) -> Result<(), Error> {
    if ext.groups.contains(ctx) { Ok(()) } else { Err(Error::UnsupportedGroup) }
}

fn handle_server_name(ext: ServerNamePayload, ctx: &Context<ServerSide>) -> Result<(), Error> {
    if ext.name == ctx.config.common.server_name { Ok(()) } else { Err(Error::IncorrectServerName) }
}

fn handle_alpn(ext: AlpnPayload, ctx: &Context<ServerSide>) -> Result<(), Error> {
    let protocol: &AlpnProtocols = ctx.common.alpn_protocol.as_ref().ok_or(Error::UnsupportedALPN)?;

    for e in &ext.protocols {
        if &e.name == protocol {
            return Ok(())
        }
    };

    Err(Error::UnsupportedALPN)
}

fn handle_status_request(ext: StatusRequestPayload, ctx: &Context<ServerSide>) -> Result<(), Error> {
    ext
}

fn handle_ec_point_formats(ext: EcPointFormatsPayload, ctx: &Context<ServerSide>) -> Result<(), Error> {
    if ext.formats.contains(ctx.) { Ok(()) } else { Err(Error::UnsupportedEcPointFormat) }
}

fn handle_signature_algorithms(ext: SignatureAlgorithmsPayload, ctx: &Context<ServerSide>) -> Result<(), Error> {
    if ext.schemes
}

fn handle_compress_certificate(ext: CompressCertificatePayload, ctx: &Context<ServerSide>) -> Result<(), Error> {
    if ext.formats.contains(ctx.) { Ok(()) } else { Err(Error::UnsupportedCompressionAlgorithm) }
}

fn handle_sct(ext: , ctx: &Context<ServerSide>) -> Result<(), Error> {
    if ext.formats.contains(ctx.config) { Ok(()) } else { Err(()) }
}

fn handle_extended_main_secret(ctx: &Context<ServerSide>) -> Result<(), Error> {
    
}

fn handle_session_ticket(ext: NewSessionTicketPayload, ctx: &Context<ServerSide>) -> Result<(), Error> {
    if ext
}

fn handle_psk_key_exchange_modes(ext: PskKeyExchangeModesPayload, ctx: &Context<ServerSide>) -> Result<(), Error> {
    if ext.modes.contains(x) { Ok(()) } else { Err() }
}

fn handle_key_share_client(ext: KeyShareClient, ctx: &Context<ServerSide>) -> Result<(), Error> {
    if ext.client_shares.contains(ctx.config) { Ok(()) } else { Err() }
}

fn handle_application_settings(ext: ApplicationSettingsPayload, ctx: &Context<ServerSide>) -> Result<(), Error> {

}

fn handle_encrypted_client_hello(ext: EncryptedClientHelloPayload, ctx: &Context<ServerSide>) -> Result<(), Error> {
    if ext.data
}
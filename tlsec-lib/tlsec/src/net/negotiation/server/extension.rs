use crate::messages::handshake::extensions::{*, client::*, server::*};

use crate::messages::handshake::handshake::server::NewSessionTicketPayload;
use crate::net::state_machine::Side;
use crate::net::state_machine::context::Context;

use crate::error::Error;

pub fn parse_extensions_server<S: Side>(ctx: &Context<S>, exts: &[Extension]) -> Result<(), Error> {
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
                    ClientExtensionPayload::ServerName(p) => handle_server_name(p, ctx),
                    ClientExtensionPayload::StatusRequest(p) => handle_status_request(p, ctx),
                    ClientExtensionPayload::SupportedGroups(p) => handle_supported_groups(p, ctx),
                    ClientExtensionPayload::EcPointFormats(p) => handle_ec_point_formats(p, ctx),
                    ClientExtensionPayload::SignatureAlgorithms(p) => handle_signature_algorithms(p, ctx),
                    ClientExtensionPayload::ALPN(p) => handle_alpn(p, ctx),
                    ClientExtensionPayload::SignedCertificateTimestamp => handle_sct(p, ctx),
                    ClientExtensionPayload::ExtendedMainSecret => handle_extended_main_secret(p, ctx),
                    ClientExtensionPayload::CompressCertificate(p) => handle_compress_certificate(p, ctx),
                    ClientExtensionPayload::SessionTicket => handle_session_ticket(p, ctx),
                    ClientExtensionPayload::SupportedVersionsClient(p) => handle_supported_versions_client(p, ctx),
                    ClientExtensionPayload::PSKKeyExchangeModes(p) => handle_psk_key_exchange_modes(p, ctx),
                    ClientExtensionPayload::KeyShareClient(p) => handle_key_share_client(p, ctx),
                    ClientExtensionPayload::ApplicationSettings(p) => handle_application_settings(p, ctx),
                    ClientExtensionPayload::EncryptedClientHello(p) => handle_encrypted_client_hello(p, ctx),
                    ClientExtensionPayload::Grease(p) => continue,
                }
            }
            _ => return Err(Error::UnexpectedMessage)
        };
    }

    Ok(());
}

fn handle_supported_versions_client<S: Side>(ext: SupportedVersionsClient, ctx: &Context<S>) -> Result<(), Error> {
    if ext.versions.contains(ctx.) { } else { }
}

fn handle_supported_groups<S: Side>(ext: SupportedGroupsPayload, ctx: &Context<S>) -> Result<(), Error> {
    if ext.groups.contains(ctx.) { } else { }
}

fn handle_server_name<S: Side>(ext: ServerNamePayload, ctx: &Context<S>) -> Result<(), Error> {
    if ext.name == ctx. { } else { }
}

fn handle_alpn<S: Side>(ext: AlpnPayload, ctx: &Context<S>) -> Result<(), Error> {
    if ext.protocols.contains(x) { } else { }
}

fn handle_status_request<S: Side>(ext: StatusRequestPayload, ctx: &Context<S>) -> Result<(), Error> {
    ext
}

fn handle_ec_point_formats<S: Side>(ext: EcPointFormatsPayload, ctx: &Context<S>) -> Result<(), Error> {
    if ext.formats.contains(ctx.) { } else { }
}

fn handle_signature_algorithms<S: Side>(ext: SignatureAlgorithmsPayload, ctx: &Context<S>) -> Result<(), Error> {
    if ext.schemes
}

fn handle_compress_certificate<S: Side>(ext: CompressCertificatePayload, ctx: &Context<S>) -> Result<(), Error> {
    if ext.formats.contains(ctx.) { } else { }
}

fn handle_sct<S: Side>(ext: , ctx: &Context<S>) -> Result<(), Error> {
    if ext.formats.contains(ctx.config) { } else { }
}

fn handle_extended_main_secret<S: Side>(ext: , ctx: &Context<S>) -> Result<(), Error> {
    
}

fn handle_session_ticket<S: Side>(ext: NewSessionTicketPayload, ctx: &Context<S>) -> Result<(), Error> {
    if ext
}

fn handle_psk_key_exchange_modes<S: Side>(ext: PskKeyExchangeModesPayload, ctx: &Context<S>) -> Result<(), Error> {
    if ext.modes.contains(x) { } else { }
}

fn handle_key_share_client<S: Side>(ext: KeyShareClient, ctx: &Context<S>) -> Result<(), Error> {
    if ext.client_shares.contains(x) { } else { }
}

fn handle_application_settings<S: Side>(ext: ApplicationSettingsPayload, ctx: &Context<S>) -> Result<(), Error> {

}

fn handle_encrypted_client_hello<S: Side>(ext: EncryptedClientHelloPayload, ctx: &Context<S>) -> Result<(), Error> {
    if ext.data
}
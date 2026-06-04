use crate::message::handshake::extensions::client::app_settings::ApplicationSettingsPayload;
use crate::message::handshake::extensions::client::key_share::KeyShareClient;
use crate::message::handshake::extensions::client::psk::PskKeyExchangeModesPayload;
use crate::message::handshake::extensions::client::sni::ServerNamePayload;
use crate::message::handshake::extensions::client::supported_groups::SupportedGroupsPayload;
use crate::message::handshake::extensions::client::supported_versions::SupportedVersionsClient;
use crate::message::alert::AlertDescription;
use crate::message::version::SupportedVersion;
use crate::message::handshake::certificate::sig_scheme::{SignatureAlgorithmsPayload, SupportedScheme};
use crate::message::handshake::extension::{Extension, ExtensionPayload};
use crate::message::handshake::extensions::alpn::{AlpnPayload, AlpnProtocols};
use crate::message::handshake::extensions::client::client::ClientExtensionPayload;
use crate::message::handshake::extensions::client::ec_point_format::{EcPointFormatsPayload, SupportedEcPointFormat};
use crate::message::handshake::extensions::compression_algo::{CompressCertificatePayload, SupportedCompressionAlgorithm};
use crate::message::handshake::extensions::key_share::SupportedNamedGroup;

use crate::net::state_machine::context::Context;
use crate::net::state_machine::side::ServerSide;

use crate::error::Error;

use bytes::*;

pub fn handle_extensions_server(
    mut ctx: &mut Context<ServerSide>,
    exts: &[Extension]
) -> Result<(), Error> {
    let mut version: Option<SupportedVersion> = None;
    let mut alpn_protocol: Option<AlpnProtocols> = None;
    let mut named_group: Option<SupportedNamedGroup> = None;
    let mut ec_point_format: Option<SupportedEcPointFormat> = None;
    let mut compression_algorithm: Option<SupportedCompressionAlgorithm> = None;
    let mut signature_scheme: Option<SupportedScheme> = None;
    let mut pbk: Option<Bytes> = None;
    let mut error: Option<Error> = None;

    for ext in exts {
        match &ext.payload {
            ExtensionPayload::Client(client_type) => {
                match client_type {
                    ClientExtensionPayload::ServerName(p) => {
                        if let Err(e) = handle_server_name(p, &mut ctx) {
                            error = Some(e);
                            break;
                        }
                    }
                    ClientExtensionPayload::SupportedGroups(p) => {
                        match handle_supported_groups(p, &mut ctx) {
                            Ok(ng) => named_group = Some(ng),
                            Err(e) => {
                                error = Some(e);
                                break;
                            }
                        }
                    }
                    ClientExtensionPayload::EcPointFormats(p) => {
                        match handle_ec_point_formats(p, &mut ctx) {
                            Ok(ecpf) => ec_point_format = Some(ecpf),
                            Err(e) => {
                                error = Some(e);
                                break;
                            }
                        }
                    }
                    ClientExtensionPayload::SignatureAlgorithms(p) => {
                        match handle_signature_algorithms(p, &mut ctx) {
                            Ok(sc) => signature_scheme = Some(sc),
                            Err(e) => {
                                error = Some(e);
                                break;
                            }
                        }
                    }
                    ClientExtensionPayload::ALPN(p) => {
                        match handle_alpn(p, &mut ctx) {
                            Ok(alpn) => alpn_protocol = Some(alpn),
                            Err(e) => {
                                error = Some(e);
                                break;
                            }
                        }
                    }
                    ClientExtensionPayload::CompressCertificate(p) => {
                        match handle_compress_certificate(p, &mut ctx) {
                            Ok(ca) => compression_algorithm = Some(ca),
                            Err(e) => {
                                error = Some(e);
                                break;
                            }
                        }
                    }
                    ClientExtensionPayload::SupportedVersionsClient(p) => {
                        match handle_supported_versions(p, &mut ctx) {
                            Ok(v) => version = Some(v),
                            Err(e) => {
                                error = Some(e);
                                break;
                            }
                        }
                    }
                    ClientExtensionPayload::PSKKeyExchangeModes(p) => {
                        if let Err(e) = handle_psk_key_exchange_modes(p, &mut ctx) {
                            error = Some(e);
                            break;
                        }
                    }
                    ClientExtensionPayload::KeyShareClient(p) => {
                        match handle_key_share(p, &mut ctx) {
                            Ok(ke) => pbk = Some(ke),
                            Err(e) => {
                                error = Some(e);
                                break;
                            }
                        }
                    }
                    ClientExtensionPayload::ApplicationSettings(p) => {
                        if let Err(e) = handle_application_settings(p, &mut ctx) {
                            error = Some(e);
                            break;
                        }
                    }
                    _ => continue,
                }
            }
            _ => return Err(Error::Alert(AlertDescription::HandshakeFailure))
        };
    }

    if let Some(e) = error {
        return Err(e);
    };

    ctx.common.alpn_protocol = alpn_protocol;
    ctx.common.compression_algorithm = compression_algorithm;
    ctx.common.ec_point_format = ec_point_format;
    ctx.common.named_group = named_group;
    ctx.common.version = version;
    ctx.common.signature_scheme = signature_scheme;
    ctx.common.peer_public_key = pbk;

    Ok(())
}

fn handle_supported_versions(
    ext: &SupportedVersionsClient,
    ctx: &mut Context<ServerSide>
) -> Result<SupportedVersion, Error> {
    for version in &ext.versions {
        for supported in &ctx.config.common.supported_versions {
            if let Some(v) = supported.compare(version) {
                return Ok(v);
            }
        }
    }

    Err(Error::Alert(AlertDescription::ProtocolVersion))
}

fn handle_supported_groups(
    ext: &SupportedGroupsPayload,
    ctx: &mut Context<ServerSide>
) -> Result<SupportedNamedGroup, Error> {
    for named_group in &ext.groups {
        for supported in &ctx.config.common.supported_named_groups {
            if let Some(ng) = supported.compare(named_group) {
                return Ok(ng);
            }
        }
    }
    
    Err(Error::Alert(AlertDescription::IllegalParameter))
}

fn handle_server_name(
    ext: &ServerNamePayload,
    ctx: &mut Context<ServerSide>
) -> Result<(), Error> {
    match &ctx.config.common.server_name {
        Some(sn) => {
            if &ext.name == sn {
                return Ok(())
            } else {
                return Err(Error::Alert(AlertDescription::UnrecognizedName))
            }
        }
        None => Ok(())
    }
}

fn handle_alpn(
    ext: &AlpnPayload,
    ctx: &mut Context<ServerSide>
) -> Result<AlpnProtocols, Error> {
    let protocol: &AlpnProtocols = ctx.common.alpn_protocol.as_ref().ok_or(Error::Alert(AlertDescription::UnsupportedExtension))?;

    for e in &ext.protocols {
        if &e.name == protocol {
            return Ok(e.name)
        }
    }

    Err(Error::Alert(AlertDescription::UnsupportedExtension))
}

fn handle_ec_point_formats(
    ext: &EcPointFormatsPayload,
    ctx: &mut Context<ServerSide>
) -> Result<SupportedEcPointFormat, Error> {
    for format in &ext.formats {
        for supported in &ctx.config.common.supported_formats {
            if let Some(ec) = supported.compare(format) {
                return Ok(ec);
            }
        }
    }
    
    Err(Error::Alert(AlertDescription::IllegalParameter))
}

fn handle_signature_algorithms(
    ext: &SignatureAlgorithmsPayload,
    ctx: &mut Context<ServerSide>
) -> Result<SupportedScheme, Error> {
    for scheme in &ext.schemes {
        for supported in &ctx.config.common.supported_signature_schemes {
            if let Some(sa) = supported.compare(scheme) {
                return Ok(sa)
            }
        }
    }
    
    Err(Error::Alert(AlertDescription::IllegalParameter))
}

fn handle_compress_certificate(
    ext: &CompressCertificatePayload,
    ctx: &mut Context<ServerSide>
) -> Result<SupportedCompressionAlgorithm, Error> {
    for algo in &ext.algorithms {
        for supported in &ctx.config.common.supported_compression_algorithms {
            if let Some(a) = supported.compare(algo) {
                return Ok(a)
            }
        }
    }

    Err(Error::Alert(AlertDescription::IllegalParameter))
}

fn handle_psk_key_exchange_modes(
    ext: &PskKeyExchangeModesPayload,
    ctx: &mut Context<ServerSide>
) -> Result<(), Error> {
    match ctx.config.common.psk_ke_mode {
        Some(mode) => {
            if ext.modes.contains(&mode) {
                return Ok(())
            }
        }
        None => return Ok(())
    }

    Err(Error::Alert(AlertDescription::IllegalParameter))
}

fn handle_key_share(
    ext: &KeyShareClient,
    ctx: &mut Context<ServerSide>
) -> Result<Bytes, Error> {
    for client_share in &ext.client_shares {
        for supported_group in &ctx.config.common.supported_named_groups {
            if supported_group.compare(&client_share.group).is_some() {
                return Ok(client_share.key_exchange.to_owned());
            }
        }
    }

    Err(Error::Alert(AlertDescription::HandshakeFailure))
}

fn handle_application_settings(
    ext: &ApplicationSettingsPayload,
    ctx: &mut Context<ServerSide>
) -> Result<(), Error> {
    match &ctx.common.alpn_protocol {
        Some(p) => {
            if &ext.protocol == p {
                return Ok(())
            }
        }
        None => {}
    }

    Err(Error::Alert(AlertDescription::IllegalParameter))
}
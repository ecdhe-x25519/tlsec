use crate::messages::handshake::extensions::{*, client::*};

use crate::net::state_machine::ServerSide;
use crate::net::state_machine::context::Context;

use crate::error::Error;

pub fn parse_extensions_server(ctx: &Context<ServerSide>, exts: &[Extension]) -> Result<(), Error> {
    for ext in exts {
        match &ext.data {
            ExtensionPayload::Client(client_type) => {
                match client_type {
                    ClientExtensionPayload::ServerName(p) => handle_server_name(p, ctx)?,
                    ClientExtensionPayload::StatusRequest(_) => continue,
                    ClientExtensionPayload::SupportedGroups(p) => handle_supported_groups(p, ctx)?,
                    ClientExtensionPayload::EcPointFormats(p) => handle_ec_point_formats(p, ctx)?,
                    ClientExtensionPayload::SignatureAlgorithms(p) => handle_signature_algorithms(p, ctx)?,
                    ClientExtensionPayload::ALPN(p) => handle_alpn(p, ctx)?,
                    ClientExtensionPayload::SignedCertificateTimestamp => continue,
                    ClientExtensionPayload::ExtendedMainSecret => continue,
                    ClientExtensionPayload::CompressCertificate(p) => handle_compress_certificate(p, ctx)?,
                    ClientExtensionPayload::SessionTicket => continue,
                    ClientExtensionPayload::SupportedVersionsClient(p) => handle_supported_versions(p, ctx)?,
                    ClientExtensionPayload::PSKKeyExchangeModes(p) => handle_psk_key_exchange_modes(p, ctx)?,
                    ClientExtensionPayload::KeyShareClient(p) => handle_key_share(p, ctx)?,
                    ClientExtensionPayload::ApplicationSettings(p) => handle_application_settings(p, ctx)?,
                    ClientExtensionPayload::EncryptedClientHello(_) => continue,
                    ClientExtensionPayload::Grease(_) => continue,
                }
            }
            _ => return Err(Error::UnsupportedExtension)
        };
    }

    Ok(())
}

fn handle_supported_versions(ext: &SupportedVersionsClient, ctx: &Context<ServerSide>) -> Result<(), Error> {
    for version in &ext.versions {
        for supported in &ctx.config.common.supported_versions {
            if let Some(_) = supported.compare(version) {
                return Ok(());
            }
        }
    }

    Err(Error::UnsupportedVersion)
}

fn handle_supported_groups(ext: &SupportedGroupsPayload, ctx: &Context<ServerSide>) -> Result<(), Error> {
    for named_group in &ext.groups {
        for supported in &ctx.config.common.supported_named_groups {
            if let Some(_) = supported.compare(named_group) {
                return Ok(());
            }
        }
    }
    
    Err(Error::UnsupportedNamedGroup)
}

fn handle_server_name(ext: &ServerNamePayload, ctx: &Context<ServerSide>) -> Result<(), Error> {
    match &ctx.config.server_name {
        Some(sn) => {
            if &ext.name == sn {
                return Ok(())
            } else {
                return Err(Error::IncorrectServerName)
            }
        }
        None => Ok(())
    }
}

fn handle_alpn(ext: &AlpnPayload, ctx: &Context<ServerSide>) -> Result<(), Error> {
    let protocol: &AlpnProtocols = ctx.common.alpn_protocol.as_ref().ok_or(Error::UnsupportedALPN)?;

    for e in &ext.protocols {
        if &e.name == protocol {
            return Ok(())
        }
    }

    Err(Error::UnsupportedALPN)
}

fn handle_ec_point_formats(ext: &EcPointFormatsPayload, ctx: &Context<ServerSide>) -> Result<(), Error> {
    for format in &ext.formats {
        for supported in &ctx.config.common.supported_formats {
            if let Some(_) = supported.compare(format) {
                return Ok(());
            }
        }
    }
    
    Err(Error::UnsupportedEcPointFormat)
}

fn handle_signature_algorithms(ext: &SignatureAlgorithmsPayload, ctx: &Context<ServerSide>) -> Result<(), Error> {
    for scheme in &ext.schemes {
        for supported in &ctx.config.common.supported_signature_schemes {
            if let Some(_) = supported.compare(scheme) {
                return Ok(())
            }
        }
    }
    
    Err(Error::UnsupportedSignatureScheme)
}

fn handle_compress_certificate(ext: &CompressCertificatePayload, ctx: &Context<ServerSide>) -> Result<(), Error> {
    for algo in &ext.algorithms {
        for supported in &ctx.config.common.supported_compression_algorithms {
            if let Some(_) = supported.compare(algo) {
                return Ok(())
            }
        }
    }

    Err(Error::UnsupportedCompressionAlgorithm)
}

fn handle_psk_key_exchange_modes(ext: &PskKeyExchangeModesPayload, ctx: &Context<ServerSide>) -> Result<(), Error> {
    match ctx.config.psk_ke_mode {
        Some(mode) => {
            if ext.modes.contains(&mode) {
                return Ok(())
            }
        }
        None => {}
    }

    Err(Error::UnsupportedPskKeMode)
}

fn handle_key_share(ext: &KeyShareClient, ctx: &Context<ServerSide>) -> Result<(), Error> {
    for client_share in &ext.client_shares {
        for supported_group in &ctx.config.common.supported_named_groups {
            if supported_group.compare(&client_share.group).is_some() {
                return Ok(());
            }
        }
    }
    
    Err(Error::UnsupportedNamedGroup)
}

fn handle_application_settings(ext: &ApplicationSettingsPayload, ctx: &Context<ServerSide>) -> Result<(), Error> {
    match &ctx.common.alpn_protocol {
        Some(p) => {
            if &ext.protocol == p {
                return Ok(())
            }
        }
        None => {}
    }

    Err(Error::UnsupportedALPN)
}
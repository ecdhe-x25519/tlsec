use crate::message::*;

use crate::net::state_machine::context::Context;
use crate::net::state_machine::ClientSide;

use super::extension::handle_extensions_client;

use crate::error::Error;

use bytes::*;

pub fn handle_certificate_client(
    mut ctx: &mut Context<ClientSide>,
    cert: &CertificatePayload
) -> Result<(), Error> {
    
    let mut error: Option<Error> = None;

    for entry in &cert.certificate_list {
        handle_extensions_client(ctx, &entry.extensions);
    }

    if let Some(e) = error {
        return Err(e);
    };

    

    Ok(())
}

pub fn handle_certificate_verify_client(
    mut ctx: &mut Context<ClientSide>,
    cert: &CertificateVerifyPayload
) -> Result<(), Error> {
    
    let mut error: Option<Error> = None;

    for entry in &cert {
        handle_extensions_client(ctx, &entry.extensions);
    }

    if let Some(e) = error {
        return Err(e);
    };

    

    Ok(())
}

pub fn handle_cert_extensions_server(
    mut ctx: &mut Context<ClientSide>,
    exts: &[Extension]
) -> Result<(), Error> {
    let mut ec_point_format: Option<SupportedEcPointFormat> = None;
    let mut compression_algorithm: Option<SupportedCompressionAlgorithm> = None;
    let mut signature_scheme: Option<SupportedScheme> = None;
    let mut error: Option<Error> = None;

    for ext in exts {
        match &ext.data {
            ExtensionType::Server(client_type) => {
                match client_type {
                    ClientExtensionPayload::StatusRequest(p) => {
                        if let Err(e) = handle_sr(p, &mut ctx) {
                            error = Some(e);
                            break;
                        }
                    }
                    ClientExtensionPayload::SignedCertificateTimestamp(p) => {
                        if let Err(e) = handle_sct(p, &mut ctx) {
                            error = Some(e);
                            break;
                        }
                    }
                    _ => return Err(Error::Alert(AlertDescription::BadCertificateStatusResponse))
                }
            }
            _ => return Err(Error::Alert(AlertDescription::HandshakeFailure))
        };
    }

    if let Some(e) = error {
        return Err(e);
    };

    ctx.common.compression_algorithm = compression_algorithm;
    ctx.common.ec_point_format = ec_point_format;
    ctx.common.signature_scheme = signature_scheme;

    Ok(())
}

fn handle_sr(cert_ext: StatusRequestPayload, ctx: &mut Context<ClientSide>) -> Result<(), Error> {
    Err(Error::Alert(AlertDescription::BadCertificate))
}

fn handle_sct(cert_ext: StatusRequestPayload, ctx: &mut Context<ClientSide>) -> Result<(), Error> {
    Err(Error::Alert(AlertDescription::BadCertificate))
}
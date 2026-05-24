use crate::messages::handshake::certificate::*;

use crate::messages::record::AlertDescription;

use crate::net::state_machine::context::Context;
use crate::net::state_machine::ClientSide;

use crate::supported::compression_algorithm::SupportedCompressionAlgorithm;
use crate::supported::signature::SupportedScheme;
use crate::supported::ec_point_format::SupportedEcPointFormat;

use super::extension::handle_extensions_client;

use crate::error::Error;

use bytes::BytesMut;

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
use crate::certificate::{verify::*, cert_store::*};

use crate::compression::{brotli::*, zlib::*};

use crate::message::handshake::{certificate::*, extensions::*};

use crate::error::*;

use super::super::general::{
    context::Context,
    side::*,
};

pub struct HandleCertificate<'a, S: Side> {
    context: &'a mut Context<S>,
}

impl<'a, S: Side> HandleCertificate<'a, S> {
    pub fn new(ctx: &'a mut Context<S>) -> Self {
        Self { context: ctx }
    }

    pub fn handle_certs_verify(
        &self,
        cert_entry: &[CertificateEntryPayload],
        cert_verify: &CertificateVerifyPayload
    ) -> TlsResult<()> {
        let transcript = &*self.context.common.transcript.hash();
        let signature_algo = &self.context.common.negotiated.signature_scheme
            .ok_or(TlsError::Alert(AlertDescription::HandshakeFailure))?;

        verify_certs(
            cert_entry,
            cert_verify,
            transcript,
            signature_algo
        )?;

        Ok(())
    }

    pub fn handle_compress_certs(
        &self,
        compressed: &CompressedCertificatePayload
    ) -> TlsResult<Vec<u8>> {
        let len_bytes = compressed.uncompressed_length;

        let length: usize = u32::from_be_bytes([
            0,
            len_bytes[0],
            len_bytes[1],
            len_bytes[2],
        ]) as usize;

        let compressed_cert = &compressed.compressed_data;

        let algo = compressed.algorithm.to_supported()
            .ok_or(TlsError::Alert(AlertDescription::BadCertificate))?;

        let negotiated = self.context.common.negotiated.compression_algorithm
            .ok_or(TlsError::Alert(AlertDescription::HandshakeFailure))?;

        if algo != negotiated {
            return Err(TlsError::Alert(AlertDescription::BadCertificate));
        }

        let decompressed = match algo {
            SupportedCompressionAlgorithm::Zlib => zlib_decompress_cert(compressed_cert)?,
            SupportedCompressionAlgorithm::Brotli => brotli_decompress_cert(compressed_cert)?,
        };

        if decompressed.len() != length {
            return Err(TlsError::Alert(AlertDescription::BadCertificate));
        }

        Ok(decompressed)
    }
}

impl<'a> HandleCertificate<'a, ClientSide> {
    pub fn handle_certs(
        &self,
        certs: &CertificatePayload
    ) -> TlsResult<Vec<CertificateEntryPayload>> {
        let common = &self.context.config.common;

        let cert_store: &CertStore = common.root_certs.as_ref()
            .ok_or(TlsError::Alert(AlertDescription::CertificateUnknown))?;

        let server_name: &String = common.supported_params.server_name.as_ref()
            .ok_or(TlsError::Alert(AlertDescription::BadCertificate))?;

        verify_certs_client(
            cert_store,
            &certs.certificate_list,
            &common.supported_params.signature_scheme.as_slice(),
            &self.context.config.verify_dns,
            Some(server_name.as_ref()),
        )?;

        Ok(certs.certificate_list.to_owned())
    }
}

impl<'a> HandleCertificate<'a, ServerSide> {
    pub fn handle_certs(
        &self,
        certs: &CertificatePayload
    ) -> TlsResult<Vec<CertificateEntryPayload>> {
        let common = &self.context.config.common;

        let cert_store: &CertStore = common.root_certs.as_ref()
            .ok_or(TlsError::Alert(AlertDescription::CertificateUnknown))?;

        verify_certs_server(
            cert_store,
            &certs.certificate_list,
            common.supported_params.signature_scheme.as_slice(),
        )?;

        Ok(certs.certificate_list.to_owned())
    }
}
use std::time::{SystemTime, UNIX_EPOCH, Duration};

use crate::certificate::cert_store::CertStore;

use crate::message::alert::AlertDescription;

use crate::message::handshake::certificate::certificate_verify::CertificateVerifyPayload;
use crate::message::handshake::certificate::{certificate::CertificateEntryPayload, sig_scheme::SupportedScheme};

use crate::error::Error;

use webpki::{TlsClientTrustAnchors, TlsServerTrustAnchors, TrustAnchor, Time, DnsNameRef, SignatureAlgorithm, EndEntityCert};

use bytes::*;

pub fn verify_certs_client(
    anchor: &CertStore,
    cert_list: &[CertificateEntryPayload],
    signature_algos: &[SupportedScheme],
    dns_check: &bool,
    server_name: Option<&str>,
) -> Result<(), Error> {
    let certificate: &Bytes = &cert_list[0].certificate_data;
    let intermediates: Vec<&[u8]> = cert_list[1..]
        .iter()
        .map(|entry| entry.certificate_data.as_ref())
        .collect();

    let end_entity_cert: EndEntityCert<'_> = EndEntityCert::try_from(certificate.as_ref())
        .map_err(|e| Error::Alert(Error::handle_webpki(e)))?;
    
    let current_time: Time = get_time()?;

    let sig_algos: Vec<&SignatureAlgorithm> = get_algo(signature_algos);

    let mut anchors: Vec<TrustAnchor<'_>> = Vec::new();

    for der in &anchor.certs {
        let trust_anchor: TrustAnchor<'_> = TrustAnchor::try_from_cert_der(&der.cert)
            .map_err(|e| Error::Alert(Error::handle_webpki(e)))?;

        anchors.push(trust_anchor);
    }

    let trust_anchors: TlsServerTrustAnchors<'_> = TlsServerTrustAnchors(&anchors);

    end_entity_cert.verify_is_valid_tls_server_cert(
        &sig_algos,
        &trust_anchors,
        &intermediates,
        current_time
    ).map_err(|e| Error::Alert(Error::handle_webpki(e)))?;

    if *dns_check {
        let sni: &str = server_name
            .ok_or(Error::Alert(AlertDescription::InternalError))?;

        let dns_name: DnsNameRef<'_> = DnsNameRef::try_from_ascii_str(&sni)
            .map_err(|_| Error::Alert(AlertDescription::BadCertificate))?;

        end_entity_cert.verify_is_valid_for_dns_name(dns_name)
            .map_err(|e| Error::Alert(Error::handle_webpki(e)))?;
    }

    Ok(())
}

pub fn verify_certs_server(
    anchor: &CertStore,
    cert_list: &[CertificateEntryPayload],
    signature_algos: &[SupportedScheme],
) -> Result<(), Error> {
    let certificate: &Bytes = &cert_list[0].certificate_data;
    let intermediates: Vec<&[u8]> = cert_list[1..]
        .iter()
        .map(|entry| entry.certificate_data.as_ref())
        .collect();

    let end_entity_cert: EndEntityCert<'_> = EndEntityCert::try_from(certificate.as_ref())
        .map_err(|e| Error::Alert(Error::handle_webpki(e)))?;
    
    let current_time: Time = get_time()?;

    let mut anchors: Vec<TrustAnchor<'_>> = Vec::new();

    let sig_algos: Vec<&SignatureAlgorithm> = get_algo(signature_algos);

    for der in &anchor.certs {
        let trust_anchor: TrustAnchor<'_> = TrustAnchor::try_from_cert_der(&der.cert)
            .map_err(|e| Error::Alert(Error::handle_webpki(e)))?;

        anchors.push(trust_anchor);
    }

    let trust_anchors: TlsClientTrustAnchors<'_> = TlsClientTrustAnchors(&anchors);

    end_entity_cert.verify_is_valid_tls_client_cert(
        &sig_algos,
        &trust_anchors,
        &intermediates,
        current_time
    ).map_err(|e| Error::Alert(Error::handle_webpki(e)))?;

    Ok(())
}

pub fn verify_certs(
    cert_entry: &[CertificateEntryPayload],
    cert_verify: &CertificateVerifyPayload,
    transcript: &[u8],
    signature_algo: &SupportedScheme,
) -> Result<(), Error> {
    match signature_algo.compare(&cert_verify.algorithm) {
        None => return Err(Error::Alert(AlertDescription::IllegalParameter)),
        Some(s) => if &s == signature_algo {} else {
            return Err(Error::Alert(AlertDescription::IllegalParameter))
        },
    }

    let end_entity_cert: EndEntityCert<'_> = EndEntityCert::try_from(cert_entry[0].certificate_data.as_ref())
        .map_err(|_| Error::Alert(AlertDescription::BadCertificate))?;

    let mut content: Vec<u8> = Vec::new();
    content.extend_from_slice(&[0x20; 64]);  // 64 spaces
    content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    content.push(0x00);
    content.extend_from_slice(transcript);

    end_entity_cert.verify_signature(signature_algo.to_algo(), &content, &cert_verify.signature)
        .map_err(|e| Error::Alert(Error::handle_webpki(e)))?;

    Ok(())
}

fn get_time() -> Result<Time, Error> {
    let now: SystemTime = SystemTime::now();
    let secs: Duration = now.duration_since(UNIX_EPOCH)
        .map_err(|e| Error::Io(format!("time to secs convertion error: {e}")))?;

    let current_time: Time = Time::from_seconds_since_unix_epoch(secs.as_secs());

    Ok(current_time)
}

fn get_algo(schemes: &[SupportedScheme]) -> Vec<&SignatureAlgorithm> {
    let sig_algos = schemes
        .iter()
        .map(|scheme| scheme.to_algo())
        .collect();

    sig_algos
}

#[cfg(test)]
mod test_webpki {
    
}
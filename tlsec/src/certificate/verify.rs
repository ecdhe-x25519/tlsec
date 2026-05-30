use std::time::{SystemTime, UNIX_EPOCH, Duration};

use crate::message::*;

use crate::error::*;

use webpki::{TlsClientTrustAnchors, TlsServerTrustAnchors, TrustAnchor, Time, DnsNameRef, SignatureAlgorithm, EndEntityCert};

use bytes::*;

pub fn parse_certs_client(
    anchor: &[u8],
    cert_list: &CertificatePayload,
    signature_algos: &[&SupportedScheme],
    dns_check: &bool,
    server_name: Option<&String>,
) -> Result<(), Error> {
    let certificate: &Bytes = &cert_list.certificate_list[0].certificate_data;
    let intermediates: Vec<&[u8]> = cert_list.certificate_list[1..]
        .iter()
        .map(|entry| entry.certificate_data.as_ref())
        .collect();

    let end_entity_cert: EndEntityCert<'_> = EndEntityCert::try_from(certificate.as_ref())
        .map_err(|e| Error::Alert(Error::handle_webpki(e)))?;
    
    let current_time: Time = Time::from_seconds_since_unix_epoch(time_secs()
        .map_err(|_| Error::Alert(AlertDescription::InternalError))?.as_secs());

    let supported_algos: Vec<&SignatureAlgorithm> = signature_algos
        .iter()
        .map(|algo: &&SupportedScheme| algo.to_algo())
        .collect();

    let trust_anchor: TrustAnchor<'_> = TrustAnchor::try_from_cert_der(&anchor)
        .map_err(|e| Error::Alert(Error::handle_webpki(e)))?;

    let anchors: Vec<TrustAnchor<'_>> = vec![trust_anchor];
    let trust_anchors: TlsServerTrustAnchors<'_> = TlsServerTrustAnchors(&anchors);

    end_entity_cert.verify_is_valid_tls_server_cert(
        &supported_algos,
        &trust_anchors,
        &intermediates,
        current_time
    ).map_err(|e| Error::Alert(Error::handle_webpki(e)))?;

    if *dns_check {
        let sni: &String = server_name.as_ref()
            .ok_or(Error::Alert(AlertDescription::InternalError))?;

        let dns_name: DnsNameRef<'_> = DnsNameRef::try_from_ascii_str(&sni)
            .map_err(|_| Error::Alert(AlertDescription::BadCertificate))?;

        end_entity_cert.verify_is_valid_for_dns_name(dns_name)
            .map_err(|e| Error::Alert(Error::handle_webpki(e)))?;
    }

    Ok(())
}

pub fn parse_certs_server(
    anchor: &[u8],
    cert_list: &CertificatePayload,
    signature_algos: &[&SupportedScheme],
) -> Result<(), Error> {
    let certificate: &Bytes = &cert_list.certificate_list[0].certificate_data;
    let intermediates: Vec<&[u8]> = cert_list.certificate_list[1..]
        .iter()
        .map(|entry| entry.certificate_data.as_ref())
        .collect();

    let end_entity_cert: EndEntityCert<'_> = EndEntityCert::try_from(certificate.as_ref())
        .map_err(|e| Error::Alert(Error::handle_webpki(e)))?;
    
    let current_time: Time = Time::from_seconds_since_unix_epoch(time_secs()
        .map_err(|_| Error::Alert(AlertDescription::InternalError))?.as_secs());

    let supported_algos: Vec<&SignatureAlgorithm> = signature_algos
        .iter()
        .map(|algo: &&SupportedScheme| algo.to_algo())
        .collect();

    let trust_anchor: TrustAnchor<'_> = TrustAnchor::try_from_cert_der(&anchor)
        .map_err(|e| Error::Alert(Error::handle_webpki(e)))?;

    let anchors: Vec<TrustAnchor<'_>> = vec![trust_anchor];
    let trust_anchors: TlsClientTrustAnchors<'_> = TlsClientTrustAnchors(&anchors);

    end_entity_cert.verify_is_valid_tls_client_cert(
        &supported_algos,
        &trust_anchors,
        &intermediates,
        current_time
    ).map_err(|e| Error::Alert(Error::handle_webpki(e)))?;

    Ok(())
}

pub fn verify_certs(
    cert_entry: &CertificatePayload,
    cert_verify: &CertificateVerifyPayload,
    transcript: &[u8],
    signature_scheme: &SupportedScheme,
) -> Result<(), Error> {
    let end_entity_cert: EndEntityCert<'_> = webpki::EndEntityCert::try_from(cert_entry.certificate_list[0].certificate_data.as_ref())
        .map_err(|_| Error::Alert(AlertDescription::BadCertificate))?;
    
    let mut content: Vec<u8> = Vec::new();
    content.extend_from_slice(&[0x20; 64]);  // 64 spaces
    content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    content.push(0x00);
    content.extend_from_slice(transcript);

    end_entity_cert.verify_signature(signature_scheme.to_algo(), &content, &cert_verify.signature)
        .map_err(|e| Error::Alert(Error::handle_webpki(e)))?;

    Ok(())
}

fn time_secs() -> Result<Duration, Error> {
    let now: SystemTime = SystemTime::now();
    let secs: Duration = now.duration_since(UNIX_EPOCH)
        .map_err(|e| Error::Io(format!("time to secs convertion error: {e}")))?;
    Ok(secs)
}

#[cfg(test)]
mod test_webpki {
    
}
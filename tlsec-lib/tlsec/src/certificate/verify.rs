use std::time::{SystemTime, UNIX_EPOCH, Duration};

use crate::messages::handshake::handshake::certificate::CertificatePayload;

use webpki::{TlsClientTrustAnchors, TlsServerTrustAnchors, TrustAnchor, Time, DnsNameRef, SignatureAlgorithm, EndEntityCert};

use bytes::BytesMut;

use super::*;
use super::supported_algos::SupportedSchemes;

pub fn parse_entry_client(
    anchor: Der,
    cert_list: CertificatePayload,
    algos: &[SupportedSchemes],
    server_name: &str,
) -> Result<(), Error> {
    let certificate: &BytesMut = &cert_list.certificate_list[0].certificate_data;
    let intermediates: Vec<&[u8]> = cert_list.certificate_list[1..]
        .iter()
        .map(|entry| entry.certificate_data.as_ref())
        .collect();

    let end_entity_cert: EndEntityCert<'_> = EndEntityCert::try_from(certificate.as_ref())
        .map_err(|_| Error::InvalidCertificate)?;
    
    let current_time: Time = Time::from_seconds_since_unix_epoch(time_secs()?.as_secs());

    let supported_algos: Vec<&SignatureAlgorithm> = algos[0..]
        .iter()
        .map(|algo: &SupportedSchemes| algo.to_algo())
        .collect();

    let trust_anchor: TrustAnchor<'_> = TrustAnchor::try_from_cert_der(&anchor.0)
        .map_err(|_| Error::InvalidCertificate)?;

    let anchors: Vec<TrustAnchor<'_>> = vec![trust_anchor];
    let trust_anchors: TlsServerTrustAnchors<'_> = TlsServerTrustAnchors(&anchors);

    end_entity_cert.verify_is_valid_tls_server_cert(
        &supported_algos,
        &trust_anchors,
        &intermediates,
        current_time
    ).map_err(|_| Error::InvalidCertificate)?;

    let dns_name: DnsNameRef<'_> = DnsNameRef::try_from_ascii_str(server_name)
        .map_err(|_| Error::InvalidCertificate)?;
    
    end_entity_cert.verify_is_valid_for_dns_name(dns_name)
        .map_err(|_| Error::InvalidCertificate)?;

    Ok(())
}

pub fn parse_entry_server(
    anchor: Der,
    cert_list: CertificatePayload,
    algos: &[SupportedSchemes],
) -> Result<(), Error> {
    let certificate: &BytesMut = &cert_list.certificate_list[0].certificate_data;
    let intermediates: Vec<&[u8]> = cert_list.certificate_list[1..]
        .iter()
        .map(|entry| entry.certificate_data.as_ref())
        .collect();

    let end_entity_cert: EndEntityCert<'_> = EndEntityCert::try_from(certificate.as_ref())
        .map_err(|_| Error::InvalidCertificate)?;
    
    let current_time: Time = Time::from_seconds_since_unix_epoch(time_secs()?.as_secs());

    let supported_algos: Vec<&SignatureAlgorithm> = algos[0..]
        .iter()
        .map(|algo: &SupportedSchemes| algo.to_algo())
        .collect();

    let trust_anchor: TrustAnchor<'_> = TrustAnchor::try_from_cert_der(&anchor.0)
        .map_err(|_| Error::InvalidCertificate)?;

    let anchors: Vec<TrustAnchor<'_>> = vec![trust_anchor];
    let trust_anchors: TlsClientTrustAnchors<'_> = TlsClientTrustAnchors(&anchors);

    end_entity_cert.verify_is_valid_tls_client_cert(
        &supported_algos,
        &trust_anchors,
        &intermediates,
        current_time
    ).map_err(|_| Error::InvalidCertificate)?;

    Ok(())
}

fn time_secs() -> Result<Duration, Error> {
    let now: SystemTime = SystemTime::now();
    let secs: Duration = now.duration_since(UNIX_EPOCH)
        .map_err(|e| Error::Io(format!("time to secs convertion error: {e}")))?;
    Ok(secs)
}
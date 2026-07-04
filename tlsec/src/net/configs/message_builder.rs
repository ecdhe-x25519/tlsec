use crate::{
    certificate::verify::sign_cert, compression::{brotli::brotli_compress_cert, zlib::zlib_compress_cert}, encryption::random::ochkagen, error::*, message::{
        handshake::{
            certificate::*, encrypted_extensions::*, extensions::*, hello::*, messages::*,
        }, serialize::Serialize, version::Version::Tls12
    }, net::{
        connection::record_layer::RecordLayer, general::{context::Context, side::*}
    }
};

use bytes::*;

pub struct MessageBuilder<'a, S: Side> {
    context: &'a mut Context<S>,
    record_layer: &'a mut RecordLayer,
    hello: &'a HandshakeMessage,
}

impl<'a, S: Side> MessageBuilder<'a, S> {
    pub fn new(context: &'a mut Context<S>, hello: &'a HandshakeMessage, record_layer: &'a mut RecordLayer) -> Self {
        Self {
            context,
            record_layer,
            hello,
        }
    }
}

impl<'a> MessageBuilder<'a, ServerSide> {
    pub fn build_hello(&mut self) -> TlsResult<HandshakeMessage> {
        let cs = &self.context.common.negotiated.cipher_suite
            .ok_or(TlsError::Alert(AlertDescription::HandshakeFailure))?;

        let ch: &ClientHelloPayload = match &self.hello.payload {
            HandshakePayload::ClientHello(ch) => ch,
            _ => return Err(TlsError::Alert(AlertDescription::UnexpectedMessage)),
        };

        let mut random = [0u8; 32];
        let mut is_hrr = false;
        if self.context.common.negotiated.hrr.is_some() {
            random = HRR_RANDOM;
            is_hrr = true;
        } else {
            ochkagen(&mut random)?;
        }

        let sh = ServerHelloPayload {
            legacy_version: Tls12,
            random,
            legacy_session_id_echo: ch.legacy_session_id.clone(),
            cipher_suite: cs.to_unsupported(),
            legacy_compression_method: CompressionMethod::Null,
            extensions: self.build_extensions()?,
            is_hrr,
        };

        Ok(HandshakeMessage {
            handshake_type: HandshakeType::ServerHello,
            payload: HandshakePayload::ServerHello(sh),
            raw: None
        })
    }

    pub fn build_encrypted_extensions(&mut self) -> TlsResult<HandshakeMessage> {
        let extensions = self.build_extensions()?;

        let ee = EncryptedExtensionsPayload {
            extensions,
        };

        Ok(HandshakeMessage {
            handshake_type: HandshakeType::EncryptedExtensions,
            payload: HandshakePayload::EncryptedExtensions(ee),
            raw: None
        })
    }

    fn build_extensions(&mut self) -> TlsResult<Vec<Extension>> {
        let mut exts: Vec<Extension> = Vec::new();

        let version = &self.context.common.negotiated.version.unwrap();

        exts.push(Extension {
            extension_type: ExtensionType::SupportedVersions,
            payload: ExtensionPayload::SupportedVersions(
                SupportedVersionsPayload { versions: vec![version.to_unsupported()] }
            )
        });

        match self.context.common.negotiated.psk_ke_mode {
            Some(PskKeyExchangeMode::PskKe) => {},
            _ => {
                let group = &self.context.common.negotiated.named_group
                    .ok_or(TlsError::Alert(AlertDescription::HandshakeFailure))?;
        
                let pub_key = &self.record_layer.cipher_state.public_key.take().unwrap();
                
                exts.push(Extension {
                    extension_type: ExtensionType::KeyShare,
                    payload: ExtensionPayload::KeyShare(KeySharePayload {
                        key_shares: vec![KeyShareEntry {
                            group: group.to_unsupported(),
                            key_exchange: Bytes::copy_from_slice(&pub_key.as_ref()),
                        }],
                    }),
                });
            }
        }

        if let Some(protocol) = &self.context.common.negotiated.alpn_protocol {
            exts.push(Extension {
                extension_type: ExtensionType::ALPN,
                payload: ExtensionPayload::ALPN(AlpnPayload {
                    protocols: vec![AlpnProtocol { name: *protocol }],
                }),
            });
        };

        // if let Some(psk_identity) = &self.context.common.cipher_state.pre_shared_key {
        //     exts.push(Extension {
        //         extension_type: ExtensionType::,
        //         payload: PreSharedKeyServer {
        //             selected_identity: 0,
        //         }.encode(),
        //     });
        // }

        Ok(exts)
    }

    pub fn build_certificate(&mut self) -> TlsResult<HandshakeMessage> {
        let certs = self.context.config.common.cert_chain.as_ref()
            .ok_or(TlsError::Alert(AlertDescription::HandshakeFailure))?;

        if certs.is_empty() {
            return Err(TlsError::Alert(AlertDescription::CertificateUnknown));
        }

        let certs: Vec<CertificateEntryPayload> = certs
            .into_iter()
            .map(|cert_data| CertificateEntryPayload {
                certificate_data: Bytes::copy_from_slice(&cert_data.cert),
                extensions: vec![],
            })
            .collect();
        
        let cert_payload = CertificatePayload {
            certificate_request_context: Bytes::new(),
            certificate_list: certs,
        };

        if let Some(algo) = &self.context.common.negotiated.compression_algorithm {
            let mut raw_cert = BytesMut::new();
            cert_payload.encode(&mut raw_cert);
            
            let compressed = match algo {
                SupportedCompressionAlgorithm::Brotli => brotli_compress_cert(&raw_cert)?,
                SupportedCompressionAlgorithm::Zlib => zlib_compress_cert(&raw_cert)?,
            };

            let compressed_msg = CompressedCertificatePayload {
                algorithm: algo.to_unsupported(),
                uncompressed_length: {
                    let len = raw_cert.len() as u32;
                    let len_bytes = len.to_be_bytes();
                    [len_bytes[1], len_bytes[2], len_bytes[3]]
                },
                compressed_data: Bytes::from(compressed),
            };

            return Ok(HandshakeMessage {
                handshake_type: HandshakeType::CompressedCertificate,
                payload: HandshakePayload::CompressedCertificate(compressed_msg),
                raw: None
            })
        } else {
            return Ok(HandshakeMessage {
                handshake_type: HandshakeType::Certificate,
                payload: HandshakePayload::Certificate(cert_payload),
                raw: None
            })
        }
    }

    pub fn build_certificate_verify(&mut self) -> TlsResult<HandshakeMessage> {
        let private_key = self.record_layer.encrypter.as_ref()
            .ok_or(TlsError::Alert(AlertDescription::HandshakeFailure))?;
        
        let transcript = &self.context.common.transcript.hash();
    
        let sc = &self.context.common.negotiated.signature_scheme
            .ok_or(TlsError::Alert(AlertDescription::HandshakeFailure))?;

        let mut content = Vec::new();
        content.extend_from_slice(&[0x20; 64]);  // 64 spaces
        content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        content.push(0x00);
        content.extend_from_slice(transcript);

        let cert = sign_cert(private_key.key(), &content, sc)?;
        
        let cv = CertificateVerifyPayload {
            algorithm: sc.to_unsupported(),
            signature: Bytes::copy_from_slice(&cert),
        };

        Ok(HandshakeMessage {
            handshake_type: HandshakeType::CertificateVerify,
            payload: HandshakePayload::CertificateVerify(cv),
            raw: None
        })
    }

    pub fn build_finished(&mut self) -> TlsResult<HandshakeMessage> {
        let hash = self.context.common.transcript.hash();

        let finished = FinishedPayload {
            verify_data: Bytes::copy_from_slice(&hash),
        };

        Ok(HandshakeMessage {
            handshake_type: HandshakeType::Finished,
            payload: HandshakePayload::Finished(finished),
            raw: None
        })
    }
}

impl<'a> MessageBuilder<'a, ClientSide> {
    pub fn build_hello(&mut self) {

    }

    pub fn build_certificate(&mut self) {

    }

    pub fn build_certificate_verify(&mut self) {

    }

    pub fn build_finished(&mut self) {

    }
}
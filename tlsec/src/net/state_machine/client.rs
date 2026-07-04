use bytes::BytesMut;

use crate::{
    error::*, message::{handshake::{
        certificate::*,

        encrypted_extensions::EncryptedExtensionsPayload,

        hello::*,

        messages::*,
    }, serialize::Serialize}, net::{connection::record_layer::RecordLayer, negotiation::{
        certificate::HandleCertificate, extensions::HandleExtensions, hello::HandleHello
    }}
};

use super::super::{
    general::{
        side::*,
        state::*,
        context::Context,
    },
    configs::message_builder::*,
};

pub struct ExpectServerHello;

impl ConnState<ClientSide> for ExpectServerHello {
    fn handle(
        self: Box<Self>,
        ctx: &mut Context<ClientSide>,
        record_layer: &mut RecordLayer,
        msg: HandshakeMessage,
    ) -> TlsResult<NextState<ClientSide>>
    {
        ctx.common.transcript.update(&msg.raw.as_ref().unwrap());

        let server_hello: ServerHelloPayload = match msg.payload {
            HandshakePayload::ServerHello(ch) => ch,
            _ => return Err(TlsError::Alert(AlertDescription::UnexpectedMessage)),
        };

        let mut hh = HandleHello::new(ctx);
        hh.select_cipher_suite(&server_hello)?;
        hh.select_compression_method(&server_hello)?;

        let mut he = HandleExtensions::new(ctx, &mut record_layer.cipher_state);
        he.handle_extensions(&server_hello.extensions)?;

        let cipher_suite: &SupportedCipherSuite = &ctx.common.negotiated.cipher_suite
            .ok_or(TlsError::Alert(AlertDescription::HandshakeFailure))?;

        let algo = &ctx.common.negotiated.named_group
            .ok_or(TlsError::Alert(AlertDescription::HandshakeFailure))?;

        record_layer.derive_hs_keys(
            cipher_suite,
            &ctx.common.transcript,
            algo,
            true,
        )?;

        Ok(NextState::new(ExpectEncryptedExtensions, None))
    }

    fn finished(&self) -> bool {
        false
    }
}

pub struct ExpectEncryptedExtensions;

impl ConnState<ClientSide> for ExpectEncryptedExtensions {
    fn handle(
        self: Box<Self>,
        ctx: &mut Context<ClientSide>,
        record_layer: &mut RecordLayer,
        msg: HandshakeMessage,
    ) -> TlsResult<NextState<ClientSide>>
    {
        ctx.common.transcript.update(&msg.raw.as_ref().unwrap());

        let server_ee: EncryptedExtensionsPayload = match msg.payload {
            HandshakePayload::EncryptedExtensions(ch) => ch,
            _ => return Err(TlsError::Alert(AlertDescription::UnexpectedMessage)),
        };

        let mut he = HandleExtensions::new(ctx, &mut record_layer.cipher_state);
        he.handle_extensions(&server_ee.extensions)?;

        Ok(NextState::new(ExpectCertificate, None))
    }

    fn finished(&self) -> bool {
        false
    }
}

pub struct ExpectCertificate;

impl ConnState<ClientSide> for ExpectCertificate {
    fn handle(
        self: Box<Self>,
        ctx: &mut Context<ClientSide>,
        _record_layer: &mut RecordLayer,
        msg: HandshakeMessage,
    ) -> TlsResult<NextState<ClientSide>>
    {
        ctx.common.transcript.update(&msg.raw.as_ref().unwrap());

        let ch = HandleCertificate::new(ctx);

        let server_certificate = match msg.payload {
            HandshakePayload::Certificate(sc) => sc,
            HandshakePayload::CompressedCertificate(sc) => {
                let raw_cert = ch.handle_compress_certs(&sc)?;

                let mut buf = BytesMut::from(raw_cert.as_slice());
                let zov_svo = CertificatePayload::decode(&mut buf)?;
                zov_svo
            },
            _ => return Err(TlsError::Alert(AlertDescription::UnexpectedMessage)),
        };

        let certificate = ch.handle_certs(&server_certificate)?;

        Ok(NextState::new(ExpectCertificateVerify {certificate}, None))
    }

    fn finished(&self) -> bool {
        false
    }
}

pub struct ExpectCertificateVerify {
    pub certificate: Vec<CertificateEntryPayload>,
}

impl ConnState<ClientSide> for ExpectCertificateVerify {
    fn handle(
        self: Box<Self>,
        ctx: &mut Context<ClientSide>,
        record_layer: &mut RecordLayer,
        msg: HandshakeMessage,
    ) -> TlsResult<NextState<ClientSide>>
    {
        ctx.common.transcript.update(&msg.raw.as_ref().unwrap());

        let ch = HandleCertificate::new(ctx);

        let server_certificate_verify: &CertificateVerifyPayload = match &msg.payload {
            HandshakePayload::CertificateVerify(ch) => ch,
            _ => return Err(TlsError::Alert(AlertDescription::UnexpectedMessage)),
        };

        ch.handle_certs_verify(&self.certificate, &server_certificate_verify,)?;

        let mut output = MessageBuilder::new(ctx, &msg, record_layer);
        output.build_finished();

        Ok(NextState::new(ExpectServerFinished, None))
    }

    fn finished(&self) -> bool {
        false
    }
}

pub struct ExpectServerFinished;

impl ConnState<ClientSide> for ExpectServerFinished {
    fn handle(
        self: Box<Self>,
        ctx: &mut Context<ClientSide>,
        record_layer: &mut RecordLayer,
        msg: HandshakeMessage,
    ) -> TlsResult<NextState<ClientSide>>
    {        
        let server_finished: FinishedPayload = match msg.payload {
            HandshakePayload::Finished(ch) => ch,
            _ => return Err(TlsError::Alert(AlertDescription::UnexpectedMessage)),
        };

        let cipher_suite: &SupportedCipherSuite = &ctx.common.negotiated.cipher_suite
            .ok_or(TlsError::Alert(AlertDescription::HandshakeFailure))?;

        record_layer.derive_ap_keys(
            cipher_suite,
            true
        )?;

        if server_finished.verify_data.as_ref() == ctx.common.transcript.hash() {
            if ctx.config.common.enable_ktls {
                record_layer.enable_ktls()?;
            }
            
            ctx.common.transcript.update(&msg.raw.as_ref().unwrap());

            return Ok(NextState::new(ClientConnected, None))
        }

        Err(TlsError::Alert(AlertDescription::HandshakeFailure))
    }

    fn finished(&self) -> bool {
        false
    }
}

pub struct ClientConnected;

impl ConnState<ClientSide> for ClientConnected {
    fn handle(
        self: Box<Self>,
        _ctx: &mut Context<ClientSide>,
        _record_layer: &mut RecordLayer,
        _msg: HandshakeMessage,
    ) -> TlsResult<NextState<ClientSide>>
    {
        Err(TlsError::Alert(AlertDescription::UnexpectedMessage))
    }

    fn finished(&self) -> bool {
        true
    }
}
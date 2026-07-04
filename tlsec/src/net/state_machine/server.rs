use bytes::BytesMut;

use crate::{
    error::*, message::{handshake::{
        certificate::*,

        hello::*,

        messages::*,
    }, serialize::Serialize}, net::{configs::message_builder::*, connection::record_layer::RecordLayer, negotiation::{
        certificate::HandleCertificate, extensions::HandleExtensions, hello::HandleHello,
    }}
};

use super::super::{
    general::{
        side::*,
        state::*,
        context::Context,
    }
};

pub struct ExpectClientHello;

impl ConnState<ServerSide> for ExpectClientHello {
    fn handle(
        self: Box<Self>,
        ctx: &mut Context<ServerSide>,
        record_layer: &mut RecordLayer,
        msg: HandshakeMessage,
    ) -> TlsResult<NextState<ServerSide>>
    {
        ctx.common.transcript.update(&msg.raw.as_ref().unwrap());

        let client_hello: &ClientHelloPayload = match &msg.payload {
            HandshakePayload::ClientHello(ch) => ch,
            _ => return Err(TlsError::Alert(AlertDescription::UnexpectedMessage)),
        };

        let mut hh = HandleHello::new(ctx);
        hh.select_cipher_suite(&client_hello)?;
        hh.select_compression_method(&client_hello)?;

        let mut he = HandleExtensions::new(ctx, &mut record_layer.cipher_state);
        he.handle_extensions(&client_hello.extensions)?;
        
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

        if ctx.config.client_auth {
            return Ok(NextState::new(ExpectClientCertificate, None))
        };

        let mut output: Vec<HandshakeMessage> = Vec::new();

        if ctx.config.common.cert_chain.is_some() {
            let mut mb = MessageBuilder::new(ctx, &msg, record_layer);
            output.push(mb.build_hello()?);
            output.push(mb.build_encrypted_extensions()?);
            output.push(mb.build_certificate()?);
            output.push(mb.build_certificate_verify()?);
        } else {
            let mut mb = MessageBuilder::new(ctx, &msg, record_layer);
            output.push(mb.build_hello()?);
            output.push(mb.build_encrypted_extensions()?);
        }

        Ok(NextState::new(ExpectClientFinished, Some(output)))
    }

    fn finished(&self) -> bool {
        false
    }
}

pub struct ExpectClientCertificate;

impl ConnState<ServerSide> for ExpectClientCertificate {
    fn handle(
        self: Box<Self>,
        ctx: &mut Context<ServerSide>,
        _record_layer: &mut RecordLayer,
        msg: HandshakeMessage,
    ) -> TlsResult<NextState<ServerSide>>
    {
        ctx.common.transcript.update(&msg.raw.as_ref().unwrap());

        let ch = HandleCertificate::new(ctx);

        let client_certificate = match msg.payload {
            HandshakePayload::Certificate(sc) => sc,
            HandshakePayload::CompressedCertificate(sc) => {
                let raw_cert = ch.handle_compress_certs(&sc)?;

                let mut buf = BytesMut::from(raw_cert.as_slice());
                let zov_svo = CertificatePayload::decode(&mut buf)?;
                zov_svo
            },
            _ => return Err(TlsError::Alert(AlertDescription::UnexpectedMessage)),
        };

        let certificate = ch.handle_certs(&client_certificate)?;

        Ok(NextState::new(ExpectClientCertificateVerify {certificate}, None ))
    }

    fn finished(&self) -> bool {
        false
    }
}

pub struct ExpectClientCertificateVerify {
    pub certificate: Vec<CertificateEntryPayload>,
}

impl ConnState<ServerSide> for ExpectClientCertificateVerify {
    fn handle(
        self: Box<Self>,
        ctx: &mut Context<ServerSide>,
        _record_layer: &mut RecordLayer,
        msg: HandshakeMessage,
    ) -> TlsResult<NextState<ServerSide>>
    {
        ctx.common.transcript.update(&msg.raw.as_ref().unwrap());

        let ch = HandleCertificate::new(ctx);

        let client_certificate_verify: CertificateVerifyPayload = match msg.payload {
            HandshakePayload::CertificateVerify(ch) => ch,
            _ => return Err(TlsError::Alert(AlertDescription::UnexpectedMessage)),
        };

        ch.handle_certs_verify(&self.certificate, &client_certificate_verify)?;

        Ok(NextState::new(ExpectClientFinished, None))
    }

    fn finished(&self) -> bool {
        false
    }
}

pub struct ExpectClientFinished;

impl ConnState<ServerSide> for ExpectClientFinished {
    fn handle(
        self: Box<Self>,
        ctx: &mut Context<ServerSide>,
        record_layer: &mut RecordLayer,
        msg: HandshakeMessage,
    ) -> TlsResult<NextState<ServerSide>>
    {
        let client_finished: FinishedPayload = match msg.payload {
            HandshakePayload::Finished(ch) => ch,
            _ => return Err(TlsError::Alert(AlertDescription::UnexpectedMessage)),
        };

        let cipher_suite: &SupportedCipherSuite = &ctx.common.negotiated.cipher_suite
            .ok_or(TlsError::Alert(AlertDescription::HandshakeFailure))?;

        record_layer.derive_ap_keys(
            cipher_suite,
            true,
        )?;

        if client_finished.verify_data.as_ref() == ctx.common.transcript.hash() {
            if ctx.config.common.enable_ktls {
                record_layer.enable_ktls()?;
            }
            
            ctx.common.transcript.update(&msg.raw.as_ref().unwrap());

            return Ok(NextState::new(ServerConnected, None))
        }

        Err(TlsError::Alert(AlertDescription::HandshakeFailure))
    }

    fn finished(&self) -> bool {
        false
    }
}

pub struct ServerConnected;

impl ConnState<ServerSide> for ServerConnected {
    fn handle(
        self: Box<Self>,
        _ctx: &mut Context<ServerSide>,
        _record_layer: &mut RecordLayer,
        _msg: HandshakeMessage,
    ) -> TlsResult<NextState<ServerSide>>
    {
        Err(TlsError::Alert(AlertDescription::UnexpectedMessage))
    }

    fn finished(&self) -> bool {
        true
    }
}
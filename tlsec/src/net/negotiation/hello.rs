use crate::{error::*, message::handshake::hello::*};

use super::super::{
    general::{
        side::*,
        context::Context,
    }
};

use brevno::*;

pub struct HandleHello<'a, S: Side> {
    context: &'a mut Context<S>,
}

impl<'a, S: Side> HandleHello<'a, S> {
    pub fn new(context: &'a mut Context<S>) -> Self {
        Self {
            context,
        }
    }
}

impl<'a> HandleHello<'a, ServerSide> {
    pub fn select_cipher_suite(
        &mut self,
        hello: &ClientHelloPayload
    ) -> TlsResult<()> {
        let server_css = &self.context.config.common.supported_params.cipher_suite;
        let client_cs = &hello.cipher_suites;

        for cs in client_cs {
            let scs = &cs.to_supported();
            if scs.is_some() && server_css.contains(&scs.unwrap()) {
                self.context.common.negotiated.cipher_suite = *scs;
                return Ok(());
            }
        }

        error!("No supported ciphers");
        Err(TlsError::Alert(AlertDescription::IllegalParameter))
    }

    pub fn select_compression_method(
        &mut self,
        hello: &ClientHelloPayload
    ) -> TlsResult<()> {
        let server_cms = &self.context.config.common.supported_params.compression_method;
        let client_cm = &hello.legacy_compression_methods;

        for cm in client_cm {
            let scm = &cm.to_supported();
            if scm.is_some() && server_cms.contains(&scm.unwrap()) {
                self.context.common.negotiated.compression_method = *scm;
                return Ok(());
            }
        }

        error!("No supported compression methods");
        Err(TlsError::Alert(AlertDescription::IllegalParameter))
    }
}

impl<'a> HandleHello<'a, ClientSide> {
    pub fn select_cipher_suite(
        &mut self,
        hello: &ServerHelloPayload
    ) -> TlsResult<()> {
        let client_css = &self.context.config.common.supported_params.cipher_suite;

        let client_cs = &self.context.config.client_hello.cipher_suites;
        let server_cs = &hello.cipher_suite;

        if client_cs.contains(&server_cs) {
            let cs = server_cs.to_supported();
            if cs.is_some() && client_css.contains(&cs.unwrap()) {
                self.context.common.negotiated.cipher_suite = cs;
                return Ok(());
            }
        }

        error!("No supported ciphers");
        Err(TlsError::Alert(AlertDescription::IllegalParameter))
    }

    pub fn select_compression_method(
        &mut self,
        hello: &ServerHelloPayload
    ) -> TlsResult<()> {
        let client_cms = &self.context.config.common.supported_params.compression_method;

        let client_cm = &self.context.config.client_hello.legacy_compression_methods;
        let server_cm = hello.legacy_compression_method;

        if client_cm.contains(&server_cm) {
            let cm = server_cm.to_supported();
            if cm.is_some() && client_cms.contains(&cm.unwrap()) {
                self.context.common.negotiated.compression_method = cm;
                return Ok(());
            }
        }

        error!("No supported compression methods");
        Err(TlsError::Alert(AlertDescription::IllegalParameter))
    }
}
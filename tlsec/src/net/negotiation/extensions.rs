use crate::{
    error::*, message::{
        handshake::extensions::*, version::*,
    }, net::connection::record_layer::CipherState
};

use super::super::general::{
    context::Context,
    side::*,
};

use brevno::*;

use bytes::*;

pub struct HandleExtensions<'a, S: Side> {
    context: &'a mut Context<S>,
    cipher_state: &'a mut CipherState,
}

impl<'a, S: Side> HandleExtensions<'a, S> {
    pub fn new(context: &'a mut Context<S>, cipher_state: &'a mut CipherState) -> Self {
        Self { context, cipher_state }
    }
}

impl<'a> HandleExtensions<'a, ServerSide> {
    pub fn handle_extensions(
        &mut self,
        exts: &[Extension],
    ) -> TlsResult<()> {
        let mut group: Option<SupportedNamedGroup> = None;
        let mut version: Option<SupportedVersion> = None;
        let mut sig_algo: Option<SupportedScheme> = None;
        let mut alpn: Option<AlpnProtocols> = None;
        let mut compression_algo: Option<SupportedCompressionAlgorithm> = None;
        let mut psk_ke_mode: Option<PskKeyExchangeMode> = None;
        let mut key_share: Option<Bytes> = None;
        let mut ecpf: Option<SupportedEcPointFormat> = None;
        let mut hrr: bool = false;

        for ext in exts {
            match &ext.payload {
                ExtensionPayload::SupportedVersions(p) => {
                    match self.handle_supported_versions(p) {
                        Ok(sv) => version = Some(sv),
                        Err(e) => return Err(e)
                    }
                }
                ExtensionPayload::SupportedGroups(p) => {
                    match self.handle_supported_groups(p) {
                        Ok(sng) => group = Some(sng),
                        Err(e) => return Err(e),
                    }
                }
                ExtensionPayload::SignatureAlgorithms(p) => {
                    match self.handle_signature_algorithms(p) {
                        Ok(sa) => sig_algo = Some(sa),
                        Err(e) => return Err(e),
                    }
                }
                ExtensionPayload::KeyShare(p) => {
                    match self.handle_key_share(p) {
                        Ok((sng, ks)) => {
                            group = Some(sng);
                            key_share = Some(ks);
                        }
                        Err(_) => hrr = true,
                    }
                }
                ExtensionPayload::ServerName(p) => {
                    self.handle_server_name(p)?
                }
                ExtensionPayload::EcPointFormats(p) => {
                    ecpf = self.handle_ec_point_formats(p)
                }
                ExtensionPayload::ALPN(p) => {
                    alpn = self.handle_alpn(p)
                }
                ExtensionPayload::CompressCertificate(p) => {
                    compression_algo = self.handle_compress_certificate(p)
                }
                ExtensionPayload::PSKKeyExchangeModes(p) => {
                    psk_ke_mode = self.handle_psk_key_exchange_modes(p)
                }
                ExtensionPayload::ApplicationSettings(p) => {
                    self.handle_application_settings(p);
                }
                _ => continue,
            }
        };

        if hrr && group.is_some() {
            self.context.common.negotiated.hrr = group;
        }

        self.context.common.negotiated.alpn_protocol = alpn;
        self.context.common.negotiated.compression_algorithm = compression_algo;
        self.context.common.negotiated.ec_point_format = ecpf;
        self.context.common.negotiated.named_group = group;
        self.context.common.negotiated.psk_ke_mode = psk_ke_mode;
        self.context.common.negotiated.signature_scheme = sig_algo;
        self.context.common.negotiated.version = version;

        self.cipher_state.peer_public_key = key_share;

        Ok(())
    }

    fn handle_supported_versions(
        &self,
        ext: &SupportedVersionsPayload,
    ) -> TlsResult<SupportedVersion> {
        let server_sv = &self.context.config.common.supported_params.version;

        for version in &ext.versions {
            if let Some(v) = version.to_supported() {
                if server_sv.contains(&v) {
                    return Ok(v)
                }
            }
        }

        error!("No common versions");
        Err(TlsError::Alert(AlertDescription::ProtocolVersion))
    }

    fn handle_supported_groups(
        &self,
        ext: &SupportedGroupsPayload,
    ) -> TlsResult<SupportedNamedGroup> {
        let server_ng = &self.context.config.common.supported_params.named_group;

        for named_group in &ext.groups {
            if let Some(ng) = named_group.to_supported() {
                if server_ng.contains(&ng) {
                    return Ok(ng)
                }
            }
        }

        error!("No common groups");
        Err(TlsError::Alert(AlertDescription::IllegalParameter))
    }

    fn handle_server_name(
        &self,
        _ext: &ServerNamePayload,
    ) -> TlsResult<()> {
        Ok(())
    }

    fn handle_alpn(
        &self,
        ext: &AlpnPayload,
    ) -> Option<AlpnProtocols> {
        if let Some(protocols) = &self.context.config.common.supported_params.alpn_protocol {
            for e in &ext.protocols {
                if protocols.contains(&e.name) {
                    return Some(e.name)
                }
            }
        }

        None
    }

    fn handle_ec_point_formats(
        &self,
        ext: &EcPointFormatsPayload,
    ) -> Option<SupportedEcPointFormat> {
        let server_ecpf = &self.context.config.common.supported_params.ec_point_format;

        for format in &ext.formats {
            if let Some(ec) = format.to_supported() {
                if server_ecpf.contains(&ec) {
                    return Some(ec);
                }
            }
        }
        
        None
    }

    fn handle_signature_algorithms(
        &self,
        ext: &SignatureAlgorithmsPayload,
    ) -> TlsResult<SupportedScheme> {
        let server_sa = &self.context.config.common.supported_params.signature_scheme;

        for scheme in &ext.schemes {
            if let Some(sa) = scheme.to_supported() {
                if server_sa.contains(&sa) {
                    return Ok(sa)
                }
            }
        }
        
        error!("No common sig algs");
        Err(TlsError::Alert(AlertDescription::IllegalParameter))
    }

    fn handle_compress_certificate(
        &self,
        ext: &CompressCertificatePayload,
    ) -> Option<SupportedCompressionAlgorithm> {
        if let Some(server_ca) = &self.context.config.common.supported_params.compression_algorithm {
            for algo in &ext.algorithms {
                if let Some(ca) = algo.to_supported() {
                    if server_ca.contains(&ca) {
                        return Some(ca);
                    }
                }
            }
        }

        None
    }

    fn handle_psk_key_exchange_modes(
        &self,
        ext: &PskKeyExchangeModesPayload,
    ) -> Option<PskKeyExchangeMode> {
        if let Some(mode) = &self.context.config.common.supported_params.psk_ke_mode {
            for ext in &ext.modes {
                if ext == mode {
                    return Some(*mode);
                }
            }
        }

        None
    }

    fn handle_key_share(
        &self,
        ext: &KeySharePayload,
    ) -> TlsResult<(SupportedNamedGroup, Bytes)> {
        let server_sg = &self.context.config.common.supported_params.named_group;

        for client_share in &ext.key_shares {
            if let Some(client_sg) = client_share.group.to_supported() {
                if server_sg.contains(&client_sg) {
                    return Ok((client_sg, client_share.key_exchange.to_owned()));
                }
            }
        }

        error!("HRR");
        Err(TlsError::Alert(AlertDescription::IllegalParameter))
    }

    fn handle_application_settings(
        &self,
        ext: &ApplicationSettingsPayload,
    ) -> Option<AlpnProtocols> {
        if let Some(proto) = &self.context.config.common.supported_params.alpn_protocol {
            if proto.contains(&ext.protocol) {
                return None;
            }
        }

        None
    }
}

impl<'a> HandleExtensions<'a, ClientSide> {    
    pub fn handle_extensions(
        &mut self,
        exts: &[Extension]
    ) -> TlsResult<()> {
        let mut group: Option<SupportedNamedGroup> = None;
        let mut version: Option<SupportedVersion> = None;
        let mut alpn: Option<AlpnProtocols> = None;
        let mut key_share: Option<Bytes> = None;

        for ext in exts {
            match &ext.payload {
                ExtensionPayload::SupportedGroups(p) => {
                    match self.handle_supported_groups(p) {
                        Ok(sng) => group = Some(sng),
                        Err(e) => return Err(e)
                    }
                }
                ExtensionPayload::SupportedVersions(p) => {
                    match self.handle_supported_versions(p) {
                        Ok(sv) => version = Some(sv),
                        Err(e) => return Err(e)
                    }
                },
                ExtensionPayload::KeyShare(p) => {
                    match self.handle_key_share(p) {
                        Ok((ng, ks)) => {
                            group = Some(ng);
                            key_share = Some(ks);
                        }
                        Err(e) => return Err(e)
                    }
                }
                ExtensionPayload::ALPN(p) => alpn = self.handle_alpn(p),
                _ => continue,
            }
        };

        self.context.common.negotiated.alpn_protocol = alpn;
        self.context.common.negotiated.named_group = group;
        self.context.common.negotiated.version = version;

        self.cipher_state.peer_public_key = key_share;

        Ok(())
    }

    fn handle_supported_versions(
        &self,
        ext: &SupportedVersionsPayload,
    ) -> TlsResult<SupportedVersion> {
        let client_sv = &self.context.config.common.supported_params.version;

        if let Some(v) = ext.versions[0].to_supported() {
            if client_sv.contains(&v) {
                return Ok(v);
            }
        }
        
        error!("No common versions");
        Err(TlsError::Alert(AlertDescription::ProtocolVersion))
    }

    fn handle_alpn(
        &self,
        ext: &AlpnPayload,
    ) -> Option<AlpnProtocols> {
        if let Some(proto) = &self.context.config.common.supported_params.alpn_protocol {
            if proto.contains(&ext.protocols[0].name) {
                return Some(ext.protocols[0].name)
            };
        };

        None
    }

    fn handle_supported_groups(
        &self,
        ext: &SupportedGroupsPayload,
    ) -> TlsResult<SupportedNamedGroup> {
        let proto = &self.context.config.common.supported_params.named_group;

        if let Some(ng) = ext.groups[0].to_supported() {
            if proto.contains(&ng) {
                return Ok(ng)
            }
        }

        error!("No common supported groups");
        Err(TlsError::Alert(AlertDescription::UnsupportedExtension))
    }

    fn handle_key_share(
        &self,
        ext: &KeySharePayload,
    ) -> TlsResult<(SupportedNamedGroup, Bytes)> {
        let client_sng = &self.context.config.common.supported_params.named_group;

        if let Some(ng) = ext.key_shares[0].group.to_supported() {
            if client_sng.contains(&ng) {
                return Ok((ng, ext.key_shares[0].key_exchange.to_owned()));
            }
        }

        error!("No common key shares");
        Err(TlsError::Alert(AlertDescription::HandshakeFailure))
    }
}
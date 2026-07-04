use std::sync::Arc;

use crate::{
    certificate::cert_store::{CertStore, Der},

    message::{
        handshake::{
            extensions::*,
            hello::*,
        },
        
        version::SupportedVersion
    },
};

pub struct TlsCommonConfig {
    pub(crate) bufs_capacity: usize,
    pub(crate) supported_params: SupportedParams,
    pub(crate) root_certs: Option<CertStore>,
    pub(crate) cert_chain: Option<Vec<Der>>,
    pub(crate) enable_ktls: bool,
}

impl TlsCommonConfig {
    pub fn new(
        bufs_capacity: usize,
        supported_params: SupportedParams,
        root_certs: Option<CertStore>,
        cert_chain: Option<Vec<Der>>,
        enable_ktls: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            bufs_capacity,
            supported_params,
            root_certs,
            cert_chain,
            enable_ktls,
        })
    }
}

pub struct SupportedParams {
    pub version: Vec<SupportedVersion>,
    pub cipher_suite: Vec<SupportedCipherSuite>,
    pub named_group: Vec<SupportedNamedGroup>,
    pub compression_method: Vec<SupportedCompressionMethod>,
    pub compression_algorithm: Option<Vec<SupportedCompressionAlgorithm>>,
    pub signature_scheme: Vec<SupportedScheme>,
    pub alpn_protocol: Option<Vec<AlpnProtocols>>,
    pub ec_point_format: Vec<SupportedEcPointFormat>,
    pub psk_ke_mode: Option<PskKeyExchangeMode>,
    pub server_name: Option<String>,
}

pub struct TlsClientConfig {
    pub(crate) common: Arc<TlsCommonConfig>,
    pub(crate) verify_dns: bool,
    pub(crate) client_hello: ClientHelloPayload,
}

impl TlsClientConfig {
    pub fn new(
        common: Arc<TlsCommonConfig>,
        verify_dns: bool,
        client_hello: ClientHelloPayload,
    ) -> Arc<Self> {
        Arc::new(Self {
            common,
            verify_dns,
            client_hello,
        })
    }
}

pub struct TlsServerConfig {
    pub(crate) common: Arc<TlsCommonConfig>,
    pub(crate) client_auth: bool,
    pub(crate) psk_identities: Option<Vec<PskIdentity>>,
}

impl TlsServerConfig {
    pub fn new(
        common: Arc<TlsCommonConfig>,
        client_auth: bool,
        psk_identities: Option<Vec<PskIdentity>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            common,
            client_auth,
            psk_identities,
        })
    }
}

pub struct PskIdentity {
    pub identity: Vec<u8>,
    pub psk: Vec<u8>,
}

impl PskIdentity {
    pub fn new(psk: Vec<u8>, identity: Vec<u8>) -> Self {
        Self { identity, psk }
    }
}
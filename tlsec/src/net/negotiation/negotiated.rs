use crate::{
    message::{
        handshake::{
            extensions::*,
            hello::*,
        }, version::SupportedVersion
    },
};

pub struct NegotiationState {
    pub version: Option<SupportedVersion>,
    pub cipher_suite: Option<SupportedCipherSuite>,
    pub alpn_protocol: Option<AlpnProtocols>,
    pub named_group: Option<SupportedNamedGroup>,
    pub ec_point_format: Option<SupportedEcPointFormat>,
    pub compression_method: Option<SupportedCompressionMethod>,
    pub compression_algorithm: Option<SupportedCompressionAlgorithm>,
    pub signature_scheme: Option<SupportedScheme>,
    pub psk_ke_mode: Option<PskKeyExchangeMode>,
    pub hrr: Option<SupportedNamedGroup>,
}

impl NegotiationState {
    pub fn new() -> Self {
        Self {
            version: None,
            cipher_suite: None,
            alpn_protocol: None,
            named_group: None,
            ec_point_format: None,
            compression_method: None,
            compression_algorithm: None,
            signature_scheme: None,
            psk_ke_mode: None,
            hrr: None,
        }
    }
}
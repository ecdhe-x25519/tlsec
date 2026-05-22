use crate::messages::handshake::*;
use crate::messages::handshake::extensions::KeyShareEntry;

use crate::net::state_machine::supported::cipher_suite::SupportedCipherSuite;

use crate::error::Error;

pub fn select_cipher_suite(
    client_suites: &[CipherSuite],
    server_suites: &[SupportedCipherSuite],
) -> Result<SupportedCipherSuite, Error> {
    for cs in client_suites {
        let supported: SupportedCipherSuite = match cs {
            CipherSuite::TlsAes128GcmSha256 => SupportedCipherSuite::Aes128,
            CipherSuite::TlsAes256GcmSha384 => SupportedCipherSuite::Aes256,
            CipherSuite::TlsChacha20Poly1305Sha256 => SupportedCipherSuite::ChaCha20,
            _ => continue,
        };

        if server_suites.contains(&supported) {
            return Ok(supported);
        }
    }
    Err(Error::UnsupportedCipherSuite)
}

pub fn verify_signature_scheme(
    scheme: &SignatureScheme,
    supported: &[SignatureScheme],
) -> bool {
    supported.contains(&scheme)
}

pub fn select_key_share_group(
    client_shares: &[KeyShareEntry],
    server_groups: &[NamedGroup],
) -> Option<NamedGroup> {
    // общая логика
}
use ring::hkdf::{self, Prk, Salt};

use crate::error::Error;
use super::cipher_suite::*;
use super::transcript::TranscriptHash;

use crate::message::handshake::hello::cipher_suite::SupportedCipherSuite;

pub struct HandshakeKeys {
    pub client: AnyCipher,
    pub server: AnyCipher,
}

impl HandshakeKeys {
    pub fn derive_handshake_keys(
        cipher_suite: &SupportedCipherSuite,
        psk: Option<&[u8]>,
        shared_secret: &[u8],
        transcript: &TranscriptHash,
    ) -> Result<HandshakeKeys, Error> {
        let algo: hkdf::Algorithm = cipher_suite.hkdf_algorithm();

        let key_len: usize = cipher_suite.hkdf_based_key_len();
        let true_kl: usize = cipher_suite.true_key_len();

        let iv_len: usize = 12;

        let hash_len: usize = cipher_suite.hash_len();
        let zero_bytes: Vec<u8> = vec![0u8; hash_len];

        let early_secret: Prk = Salt::new(algo, &[]).extract(psk.unwrap_or(&zero_bytes));
        
        let mut derived_early: Vec<u8> = vec![0u8; hash_len];
        early_secret.expand(&[b"derived"], algo)
            .map_err(|e| Error::Crypto(format!("early secret expand failed: {e}")))?
            .fill(&mut derived_early)
            .map_err(|e| Error::Crypto(format!("early secret fill error: {e}")))?;
        
        let handshake_secret: Prk = Salt::new(algo, shared_secret).extract(&derived_early);
    
        let context: Vec<u8> = transcript.hash();
        
        let client_key_shit: Vec<u8> = hkdf_expand_label(&handshake_secret, b"c hs traffic key", &context, algo, key_len)?;
        let client_key: Vec<u8> = client_key_shit[..true_kl].try_into().map_err(|e| Error::Crypto(format!("key error: {e}")))?;

        let client_iv_shit: Vec<u8> = hkdf_expand_label(&handshake_secret, b"c hs traffic iv", &context, algo, key_len)?;
        let client_iv: Vec<u8> = client_iv_shit[..iv_len].try_into().map_err(|e| Error::Crypto(format!("C HS IV error: {e}")))?;

        let server_key_shit: Vec<u8> = hkdf_expand_label(&handshake_secret, b"s hs traffic key", &context, algo, key_len)?;
        let server_key: Vec<u8> = server_key_shit[..true_kl].try_into().map_err(|e| Error::Crypto(format!("key error: {e}")))?;

        let server_iv_shit: Vec<u8> = hkdf_expand_label(&handshake_secret, b"s hs traffic iv", &context, algo, key_len)?;
        let server_iv: Vec<u8> = server_iv_shit[..iv_len].try_into().map_err(|e| Error::Crypto(format!("C HS IV error: {e}")))?;

        Ok(Self {
            client: cipher_suite.create_cipher(client_key, client_iv)?,
            server: cipher_suite.create_cipher(server_key, server_iv)?,
        })
    }
}

pub struct ApplicationKeys {
    pub client: AnyCipher,
    pub server: AnyCipher,
}

impl ApplicationKeys {
    pub fn derive_application_keys(
        cipher_suite: &SupportedCipherSuite,
        psk: Option<&[u8]>,
        shared_secret: &[u8],
    ) -> Result<ApplicationKeys, Error> {
        let algo: hkdf::Algorithm = cipher_suite.hkdf_algorithm();
    
        let key_len: usize = cipher_suite.hkdf_based_key_len();
        let true_kl: usize = cipher_suite.true_key_len();

        let iv_len: usize = 12;

        let hash_len: usize = cipher_suite.hash_len();
        let zero_bytes: Vec<u8> = vec![0u8; hash_len];

        let early_secret: Prk = Salt::new(algo, &[]).extract(psk.unwrap_or(&zero_bytes));

        let mut derived_early: Vec<u8> = vec![0u8; hash_len];
        early_secret.expand(&[b"derived"], algo)
            .map_err(|e| Error::Crypto(format!("early secret expand failed: {e}")))?
            .fill(&mut derived_early)
            .map_err(|e| Error::Crypto(format!("early secret fill error: {e}")))?;

        let handshake_secret: Prk = Salt::new(algo, shared_secret).extract(&derived_early);

        let mut derived: Vec<u8> = vec![0u8; hash_len];
        handshake_secret.expand(&[b"derived"], algo)
            .map_err(|e| Error::Crypto(format!("master secret expand error: {e}")))?
            .fill(&mut derived)
            .map_err(|e| Error::Crypto(format!("master secret fill error: {e}")))?;
        let master_secret: Prk = Salt::new(algo, &[]).extract(&derived);

        let client_key_shit: Vec<u8> = hkdf_expand_label(&master_secret, b"c ap traffic key", b"", algo, key_len)?;
        let client_key: Vec<u8> = client_key_shit[..true_kl].try_into().map_err(|e| Error::Crypto(format!("key error: {e}")))?;

        let client_iv_shit: Vec<u8> = hkdf_expand_label(&master_secret, b"c ap traffic iv", b"", algo, key_len)?;
        let client_iv: Vec<u8> = client_iv_shit[..iv_len].try_into().map_err(|e| Error::Crypto(format!("C HS IV error: {e}")))?;

        let server_key_shit: Vec<u8> = hkdf_expand_label(&master_secret, b"s ap traffic key", b"", algo, key_len)?;
        let server_key: Vec<u8> = server_key_shit[..true_kl].try_into().map_err(|e| Error::Crypto(format!("key error: {e}")))?;

        let server_iv_shit: Vec<u8> = hkdf_expand_label(&master_secret, b"s ap traffic iv", b"", algo, key_len)?;
        let server_iv: Vec<u8> = server_iv_shit[..iv_len].try_into().map_err(|e| Error::Crypto(format!("C HS IV error: {e}")))?;

        Ok(Self {
            client: cipher_suite.create_cipher(client_key, client_iv)?,
            server: cipher_suite.create_cipher(server_key, server_iv)?,
        })
    }
}

fn hkdf_expand_label(
    prk: &Prk, 
    label: &[u8], 
    context: &[u8], 
    algorithm: hkdf::Algorithm,
    length: usize,
) -> Result<Vec<u8>, Error> {
    let mut info: Vec<u8> = Vec::new();
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push((label.len() + 6) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    let binding: [&[u8]; 1] = [&info];
    let okm: hkdf::Okm<'_, hkdf::Algorithm> = prk.expand(&binding, algorithm)
        .map_err(|e| Error::Crypto(format!("OKM error: {e}")))?;

    let mut out: Vec<u8> = vec![0u8; length];
    okm.fill(&mut out)
    .map_err(|e| Error::Crypto(format!("OKM fill error: {e}")))?;
    
    Ok(out)
}

#[cfg(test)]
mod test_key_schedule {
    use crate::encryption::key_exchange::*;
    use crate::encryption::key_schedule::*;
    use crate::encryption::transcript::TranscriptHash;
    use crate::encryption::random::Random;

    use crate::message::handshake::extensions::key_share::SupportedNamedGroup;

    use ring::digest::SHA256;

    #[test]
    fn test_aes128() {
        let rng: Random = Random::new();
        let algo: SupportedNamedGroup = SupportedNamedGroup::X25519;
        let transcript: TranscriptHash = TranscriptHash::new(&SHA256);
        let cipher_suite: &SupportedCipherSuite = &SupportedCipherSuite::Aes128;

        let (priv_key, pub_key) = generate_key_pair(&rng, &algo).unwrap();

        let ss: Vec<u8> = compute_shared_secret(priv_key, pub_key.as_ref(), &algo).unwrap();

        HandshakeKeys::derive_handshake_keys(&cipher_suite, None, &ss, &transcript).unwrap();

        ApplicationKeys::derive_application_keys(&cipher_suite, None, &ss).unwrap();
    }

    #[test]
    fn test_aes256() {
        let rng: Random = Random::new();
        let algo: SupportedNamedGroup = SupportedNamedGroup::X25519;
        let transcript: TranscriptHash = TranscriptHash::new(&SHA256);
        let cipher_suite: &SupportedCipherSuite = &SupportedCipherSuite::Aes256;

        let (priv_key, pub_key) = generate_key_pair(&rng, &algo).unwrap();

        let ss: Vec<u8> = compute_shared_secret(priv_key, pub_key.as_ref(), &algo).unwrap();

        HandshakeKeys::derive_handshake_keys(&cipher_suite, None, &ss, &transcript).unwrap();

        ApplicationKeys::derive_application_keys(&cipher_suite, None, &ss).unwrap();
    }

    #[test]
    fn test_chacha20() {
        let rng: Random = Random::new();
        let algo: SupportedNamedGroup = SupportedNamedGroup::X25519;
        let transcript: TranscriptHash = TranscriptHash::new(&SHA256);
        let cipher_suite: &SupportedCipherSuite = &SupportedCipherSuite::ChaCha20;

        let (priv_key, pub_key) = generate_key_pair(&rng, &algo).unwrap();

        let ss: Vec<u8> = compute_shared_secret(priv_key, pub_key.as_ref(), &algo).unwrap();

        HandshakeKeys::derive_handshake_keys(&cipher_suite, None, &ss, &transcript).unwrap();

        ApplicationKeys::derive_application_keys(&cipher_suite, None, &ss).unwrap();
    }
}
use ring::agreement::{EphemeralPrivateKey, PublicKey, UnparsedPublicKey, agree_ephemeral};

use crate::message::handshake::extensions::*;

use crate::error::*;

use super::random::init_rng;

pub fn generate_key_pair(
    algo: &SupportedNamedGroup
) -> TlsResult<(EphemeralPrivateKey, PublicKey)> {
    let rng = init_rng();

    let private_key: EphemeralPrivateKey = EphemeralPrivateKey::generate(algo.to_curve(), rng)
        .map_err(|e| TlsError::Crypto(format!("private key generation error: {e}")))?;

    let public_key: PublicKey = private_key.compute_public_key()
        .map_err(|e| TlsError::Crypto(format!("public key generation error: {e}")))?;

    Ok((private_key, public_key))
}

pub fn compute_shared_secret(
    private_key: EphemeralPrivateKey,
    peer_public: &[u8],
    algo: &SupportedNamedGroup,
) -> TlsResult<Vec<u8>> {
    let peer_pub: UnparsedPublicKey<&[u8]> = UnparsedPublicKey::new(algo.to_curve(), peer_public);
    
    let shared_secret: Vec<u8> = agree_ephemeral(private_key, &peer_pub, |secret: &[u8]| secret.to_vec())
        .map_err(|e| TlsError::Crypto(format!("failed to compute shared secret: {e}")))?;
    
    Ok(shared_secret)
}

#[cfg(test)]
mod test_key_exchange {
    use crate::encryption::key_exchange::*;

    #[test]
    fn x25519() {
        let algo: SupportedNamedGroup = SupportedNamedGroup::X25519;

        let (priv_key, pub_key) = generate_key_pair(&algo).unwrap();

        compute_shared_secret(priv_key, pub_key.as_ref(), &algo).unwrap();
    }

    #[test]
    fn secp256r1() {
        let algo: SupportedNamedGroup = SupportedNamedGroup::Secp256R1;

        let (priv_key, pub_key) = generate_key_pair(&algo).unwrap();

        compute_shared_secret(priv_key, pub_key.as_ref(), &algo).unwrap();
    }

    #[test]
    fn secp384r1() {
        let algo: SupportedNamedGroup = SupportedNamedGroup::Secp384R1;

        let (priv_key, pub_key) = generate_key_pair(&algo).unwrap();

        compute_shared_secret(priv_key, pub_key.as_ref(), &algo).unwrap();
    }
}
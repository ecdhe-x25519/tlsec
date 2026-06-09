use ring::agreement::{EphemeralPrivateKey, PublicKey, UnparsedPublicKey, agree_ephemeral};

use crate::message::handshake::extensions::key_share::SupportedNamedGroup;

use crate::error::*;

use super::random::Random;

pub fn generate_key_pair(
    random: &Random,
    algo: &SupportedNamedGroup
) -> Result<(EphemeralPrivateKey, PublicKey), TlsError> {
    let private_key: EphemeralPrivateKey = EphemeralPrivateKey::generate(algo.to_curve(), &random.0)
        .map_err(|e| TlsError::Crypto(format!("private key generation error: {e}")))?;

    let public_key: PublicKey = private_key.compute_public_key()
        .map_err(|e| TlsError::Crypto(format!("public key generation error: {e}")))?;

    Ok((private_key, public_key))
}

pub fn compute_shared_secret(
    private_key: EphemeralPrivateKey,
    peer_public: &[u8],
    algo: &SupportedNamedGroup,
) -> Result<Vec<u8>, TlsError> {
    let peer_pub: UnparsedPublicKey<&[u8]> = UnparsedPublicKey::new(algo.to_curve(), peer_public);
    
    let shared_secret: Vec<u8> = agree_ephemeral(private_key, &peer_pub, |secret: &[u8]| secret.to_vec())
        .map_err(|e| TlsError::Crypto(format!("failed to compute shared secret: {e}")))?;
    
    Ok(shared_secret)
}

#[cfg(test)]
mod test_key_exchange {
    use crate::encryption::key_exchange::*;
    use crate::encryption::random::Random;

    #[test]
    fn x25519() {
        let rng: Random = Random::new();
        let algo: SupportedNamedGroup = SupportedNamedGroup::X25519;

        let (priv_key, pub_key) = generate_key_pair(&rng, &algo).unwrap();

        compute_shared_secret(priv_key, pub_key.as_ref(), &algo).unwrap();
    }

    #[test]
    fn secp256r1() {
        let rng: Random = Random::new();
        let algo: SupportedNamedGroup = SupportedNamedGroup::Secp256R1;

        let (priv_key, pub_key) = generate_key_pair(&rng, &algo).unwrap();

        compute_shared_secret(priv_key, pub_key.as_ref(), &algo).unwrap();
    }

    #[test]
    fn secp384r1() {
        let rng: Random = Random::new();
        let algo: SupportedNamedGroup = SupportedNamedGroup::Secp384R1;

        let (priv_key, pub_key) = generate_key_pair(&rng, &algo).unwrap();

        compute_shared_secret(priv_key, pub_key.as_ref(), &algo).unwrap();
    }
}
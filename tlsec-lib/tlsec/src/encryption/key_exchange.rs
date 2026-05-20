use ring::agreement::{EphemeralPrivateKey, PublicKey, UnparsedPublicKey, Algorithm, agree_ephemeral};

use super::*;

pub fn generate_key_pair(random: Random, algo: &'static Algorithm) -> Result<(EphemeralPrivateKey, PublicKey), Error> {
    let private_key: EphemeralPrivateKey = EphemeralPrivateKey::generate(algo, &random.0)
        .map_err(|e| Error::Crypto(format!("private key generation error: {e}")))?;

    let public_key: PublicKey = private_key.compute_public_key()
        .map_err(|e| Error::Crypto(format!("public key generation error: {e}")))?;

    Ok((private_key, public_key))
}

pub fn compute_shared_secret(
    private_key: EphemeralPrivateKey,
    peer_public: &[u8],
    algo: &'static Algorithm,
) -> Result<Vec<u8>, Error> {
    let peer_pub: UnparsedPublicKey<&[u8]> = UnparsedPublicKey::new(algo, peer_public);
    
    let shared_secret: Vec<u8> = agree_ephemeral(private_key, &peer_pub, |secret: &[u8]| secret.to_vec())
        .map_err(|e| Error::Crypto(format!("failed to compute shared secret: {e}")))?;
    
    Ok(shared_secret)
}
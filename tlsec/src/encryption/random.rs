use std::sync::OnceLock;

use ring::rand::{SystemRandom, SecureRandom};

use crate::error::*;

static RNG: OnceLock<SystemRandom> = OnceLock::new();

pub fn init_rng() -> &'static SystemRandom {
    let rng = RNG.get_or_init(|| SystemRandom::new());
    rng
}

pub fn ochkagen(arr: &mut [u8]) -> TlsResult<()> {
    let rng = RNG.get().expect("RNG not initialized");
    rng.fill(arr)
        .map_err(|_| TlsError::Crypto("RNG failed".into()))?;
    Ok(())
}

#[cfg(test)]
mod test_random {
    use super::*;

    #[test]
    fn test_random() {
        init_rng();

        let mut rnd1: [u8; 32] = [0u8; 32];
        ochkagen(&mut rnd1).unwrap();

        let mut rnd2: [u8; 32] = [0u8; 32];
        ochkagen(&mut rnd2).unwrap();

        assert_ne!(rnd1, rnd2);
    }
}
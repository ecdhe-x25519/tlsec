use std::sync::OnceLock;

use ring::rand::{SystemRandom, SecureRandom};

use crate::error::*;

pub struct Random(pub SystemRandom);

impl Random {
    pub fn new() -> Self {
        let rand: SystemRandom = SystemRandom::new();
        let mut test: [u8; 1] = [0u8; 1];
        rand.fill(&mut test).expect("do rm -rf /");
        Self(rand)
    }

    pub fn ochkagen(&self, arr: &mut [u8]) -> Result<(), TlsError> {
        self.0.fill(arr)
            .map_err(|e| TlsError::Crypto(format!("secure random failed: {e}")))?;
        Ok(())
    }
}

static RANDOM: OnceLock<Random> = OnceLock::new();

pub fn get_random() -> &'static Random {
    RANDOM.get_or_init(|| Random::new())
}

#[cfg(test)]
mod test_random {
    use super::*;

    #[test]
    fn test_random() {
        let rng = Random::new();

        let mut rnd1: [u8; 32] = [0u8; 32];
        rng.ochkagen(&mut rnd1).unwrap();

        let mut rnd2: [u8; 32] = [0u8; 32];
        rng.ochkagen(&mut rnd2).unwrap();

        assert_ne!(rnd1, rnd2);
    }
}
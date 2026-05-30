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

    pub fn ochkagen(&self, arr: &mut [u8]) -> Result<(), Error> {
        self.0.fill(arr)
            .map_err(|e| Error::Crypto(format!("secure random failed: {e}")))?;
        Ok(())
    }
}

static RANDOM: OnceLock<Random> = OnceLock::new();

pub fn get_random() -> &'static Random {
    RANDOM.get_or_init(|| Random::new())
}

#[cfg(test)]
mod test_random {
    
}
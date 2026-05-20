pub mod key_exchange;
pub mod key_schedule;
pub mod supported_suites;
pub mod transcript;

use crate::error::Error;

use ring::rand::{
    SystemRandom,
    SecureRandom,
};

pub struct Random(SystemRandom);

impl Random {
    pub fn new() -> Result<Self, Error> {
        let rand: SystemRandom = SystemRandom::new();

        let mut test: [u8; 1] = [0u8; 1];
        rand.fill(&mut test).map_err(|e| Error::Crypto(format!("test random fill error: {e}")))?;

        Ok(Self(rand))
    }

    pub fn secure_random(&self, array: &mut [u8]) -> Result<(), Error> {
        self.0.fill(array).map_err(|e| Error::Crypto(format!("secure random fill error: {e}")))?;
        Ok(())
    }
}
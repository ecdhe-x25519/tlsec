use ring::digest::{Algorithm, Context};

pub struct TranscriptHash {
    pub ctx: Context,
    pub algorithm: &'static Algorithm,
}

impl TranscriptHash {
    pub fn new(algorithm: &'static Algorithm) -> Self {
        Self {
            ctx: Context::new(algorithm),
            algorithm,
        }
    }
    
    pub fn update(&mut self, data: &[u8]) {
        self.ctx.update(data);
    }
    
    pub fn hash(&self) -> Vec<u8> {
        self.ctx.clone().finish().as_ref().to_vec()
    }
    
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }

    pub fn change_algorithm(&mut self, algorithm: &'static Algorithm) {
        self.algorithm = algorithm
    }
}

#[cfg(test)]
mod test_transcript {
    
}
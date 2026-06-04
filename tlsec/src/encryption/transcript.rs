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
    use super::*;

    use ring::digest::SHA256;

    #[test]
    fn test_transcript() {
        let mut ts1: TranscriptHash = TranscriptHash::new(&SHA256);
        let mut ts2: TranscriptHash = TranscriptHash::new(&SHA256);

        let data: Vec<u8> = vec![
            0x8b, 0xd4, 0x05, 0x4f, 0xb5, 0x5b, 0x9d, 0x63,
            0xfd, 0xfb, 0xac, 0xf9, 0xf0, 0x4b, 0x9f, 0x0d,
            0x35, 0x95, 0x00, 0x46, 0xbb, 0x29, 0xd5, 0x76,
            0x8a, 0x4f, 0x21, 0xcc, 0xbc, 0x5e, 0x2d, 0x48,
        ];

        ts1.update(&data);
        ts2.update(&data);

        let zalupa1: Vec<u8> = ts1.hash();
        let zalupa2: Vec<u8> = ts2.hash();

        assert_eq!(zalupa1, zalupa2);
    }
}
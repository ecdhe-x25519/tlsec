use ring::aead::{
    Tag,
    Nonce,
    Aad,
    CHACHA20_POLY1305,
    AES_128_GCM,
    AES_256_GCM,
    LessSafeKey,
    UnboundKey,
};

use bytes::BytesMut;

use crate::error::Error;

pub trait AeadAlgorithm<const KEY_LEN: usize, const NONCE_LEN: usize> {
    fn encrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], ad: &[u8], data: &mut BytesMut) -> Result<(), Error>;
    fn decrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], ad: &[u8], data: &mut BytesMut) -> Result<(), Error>;
}

macro_rules! impl_aead {
    ($name:ident, $algo:expr, $key_len:expr, $nonce_len:expr) => {
        pub struct $name;
        
        impl AeadAlgorithm<$key_len, $nonce_len> for $name {
            fn encrypt(key: &[u8; $key_len], nonce: &[u8; $nonce_len], ad: &[u8], data: &mut BytesMut) -> Result<(), Error> {
                let unbound = UnboundKey::new($algo, key).map_err(|e| Error::Crypto(format!("invalid key: {e}")))?;
                let key = LessSafeKey::new(unbound);
                let nonce = Nonce::assume_unique_for_key(*nonce);
                let aad = Aad::from(ad);
                
                let tag_len = $algo.tag_len();
                let plaintext_len = data.len();
                data.resize(plaintext_len + tag_len, 0);
                
                let tag = key.seal_in_place_separate_tag(nonce, aad, &mut data[..plaintext_len])
                    .map_err(|e| Error::Crypto(format!("encryption error: {e}")))?;
                data[plaintext_len..].copy_from_slice(tag.as_ref());
                Ok(())
            }

            fn decrypt(key: &[u8; $key_len], nonce: &[u8; $nonce_len], ad: &[u8], data: &mut BytesMut) -> Result<(), Error> {
                let unbound: UnboundKey = UnboundKey::new($algo, key).map_err(|e| Error::Crypto(format!("invalid key: {e}")))?;
                let key: LessSafeKey = LessSafeKey::new(unbound);
                let nonce: Nonce = Nonce::assume_unique_for_key(*nonce);
                let aad: Aad<&[u8]> = Aad::from(ad);
                
                let tag_len: usize = $algo.tag_len();
                if data.len() < tag_len {
                    return Err(Error::Crypto("data too short for tag".to_string()));
                }
                
                let ciphertext_len: usize = data.len() - tag_len;
                let tag_bytes: BytesMut = data.split_off(ciphertext_len);
                let tag: Tag = Tag::try_from(tag_bytes.as_ref()).map_err(|e| Error::Crypto(format!("wrong tag length: {e}")))?;
                
                let plaintext_len: usize = key.open_in_place_separate_tag(nonce, aad, tag, &mut data[..], 0..)
                    .map_err(|e| Error::Crypto(format!("decryption failed: {e}")))?
                    .len();
                
                data.truncate(plaintext_len);
                
                Ok(())
            }
        }
    }
}

impl_aead!(ChaCha20Poly1305Sha256, &CHACHA20_POLY1305, 32, 12);
impl_aead!(Aes128GcmSha256, &AES_128_GCM, 16, 12);
impl_aead!(Aes256GcmSha384, &AES_256_GCM, 32, 12);

pub struct TlsCipher<A, const KEY_LEN: usize, const NONCE_LEN: usize>
where
    A: AeadAlgorithm<KEY_LEN, NONCE_LEN>,
{
    key: [u8; KEY_LEN],
    iv: [u8; NONCE_LEN],
    _phantom: std::marker::PhantomData<A>,
}

impl<A, const KEY_LEN: usize, const NONCE_LEN: usize> TlsCipher<A, KEY_LEN, NONCE_LEN>
where
    A: AeadAlgorithm<KEY_LEN, NONCE_LEN>,
{
    pub fn new(key: [u8; KEY_LEN], iv: [u8; NONCE_LEN]) -> Self {
        Self { key, iv, _phantom: std::marker::PhantomData }
    }
    
    pub fn encrypt(&self, seq: u64, buf: &mut BytesMut, ad: &[u8]) -> Result<(), Error> {
        let nonce: [u8; NONCE_LEN] = self.build_nonce(seq);
        A::encrypt(&self.key, &nonce, ad, buf)
    }
    
    pub fn decrypt(&self, seq: u64, buf: &mut BytesMut, ad: &[u8]) -> Result<(), Error> {
        let nonce: [u8; NONCE_LEN] = self.build_nonce(seq);
        A::decrypt(&self.key, &nonce, ad, buf)
    }
    
    fn build_nonce(&self, seq: u64) -> [u8; NONCE_LEN] {
        let mut nonce: [u8; NONCE_LEN] = self.iv;
        let seq_bytes: [u8; 8] = seq.to_le_bytes();
        for i in 0..8 {
            nonce[NONCE_LEN - 8 + i] ^= seq_bytes[i];
        }
        nonce
    }
}

pub enum AnyCipher {
    ChaCha20(TlsCipher<ChaCha20Poly1305Sha256, 32, 12>),
    Aes128(TlsCipher<Aes128GcmSha256, 16, 12>),
    Aes256(TlsCipher<Aes256GcmSha384, 32, 12>),
}

impl AnyCipher {
    pub fn encrypt(&mut self, seq: u64, buf: &mut BytesMut, ad: &[u8]) -> Result<(), Error> {
        match self {
            AnyCipher::ChaCha20(c) => c.encrypt(seq, buf, ad),
            AnyCipher::Aes128(c) => c.encrypt(seq, buf, ad),
            AnyCipher::Aes256(c) => c.encrypt(seq, buf, ad),
        }
    }
    
    pub fn decrypt(&mut self, seq: u64, buf: &mut BytesMut, ad: &[u8]) -> Result<(), Error> {
        match self {
            AnyCipher::ChaCha20(c) => c.decrypt(seq, buf, ad),
            AnyCipher::Aes128(c) => c.decrypt(seq, buf, ad),
            AnyCipher::Aes256(c) => c.decrypt(seq, buf, ad),
        }
    }
    
    pub fn key_len(&self) -> usize {
        match self {
            AnyCipher::ChaCha20(_) => 32,
            AnyCipher::Aes128(_) => 16,
            AnyCipher::Aes256(_) => 32,
        }
    }
}

#[cfg(test)]
mod test_encryption {
    
}
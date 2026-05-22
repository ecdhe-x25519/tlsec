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

use ring::hkdf::{self, HKDF_SHA256, HKDF_SHA384};
use ring::agreement::{self, ECDH_P256, ECDH_P384, X25519};
use ring::digest::{self, SHA256, SHA384};

use bytes::BytesMut;

use super::Error;

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

pub struct HandshakeKeys {
    pub client: AnyCipher,
    pub server: AnyCipher,
}

pub struct ApplicationKeys {
    pub client: AnyCipher,
    pub server: AnyCipher,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedCipherSuite {
    ChaCha20,
    Aes128,
    Aes256,
}

impl SupportedCipherSuite {
    pub fn key_len(&self) -> usize {
        match self {
            Self::ChaCha20 => 32,
            Self::Aes128 => 16,
            Self::Aes256 => 32,
        }
    }

    pub fn iv_len(&self) -> usize { 12 }

    pub fn hash_algorithm(&self) -> &'static digest::Algorithm {
        match self {
            Self::ChaCha20 => &SHA256,
            Self::Aes128 => &SHA256,
            Self::Aes256 => &SHA384,
        }
    }

    pub fn hash_len(&self) -> usize {
        match self {
            Self::ChaCha20 => 32,
            Self::Aes128 => 32,
            Self::Aes256 => 48,
        }
    }

    pub fn hkdf_algorithm(&self) -> hkdf::Algorithm {
        match self {
            Self::ChaCha20 => HKDF_SHA256,
            Self::Aes128 => HKDF_SHA256,
            Self::Aes256 => HKDF_SHA384,
        }
    }

    pub fn create_cipher(&self, key: Vec<u8>, iv: Vec<u8>) -> Result<AnyCipher, Error> {
        match self {
            Self::ChaCha20 => {
                let key_arr: [u8; 32] = key.try_into().map_err(|_| Error::Crypto("invalid key length".to_string()))?;
                let iv_arr: [u8; 12] = iv.try_into().map_err(|_| Error::Crypto("invalid iv length".to_string()))?;
                Ok(AnyCipher::ChaCha20(TlsCipher::new(key_arr, iv_arr)))
            }
            Self::Aes128 => {
                let key_arr: [u8; 16] = key.try_into().map_err(|_| Error::Crypto("invalid key length".to_string()))?;
                let iv_arr: [u8; 12] = iv.try_into().map_err(|_| Error::Crypto("invalid iv length".to_string()))?;
                Ok(AnyCipher::Aes128(TlsCipher::new(key_arr, iv_arr)))
            }
            Self::Aes256 => {
                let key_arr: [u8; 32] = key.try_into().map_err(|_| Error::Crypto("invalid key length".to_string()))?;
                let iv_arr: [u8; 12] = iv.try_into().map_err(|_| Error::Crypto("invalid iv length".to_string()))?;
                Ok(AnyCipher::Aes256(TlsCipher::new(key_arr, iv_arr)))
            }
        }
    }
}

pub enum SupportedCurves {
    X25519,
    Secp256R1,
    Secp384R1,
}

impl SupportedCurves {
    pub fn to_curve(self) -> &'static agreement::Algorithm {
        match self {
            Self::X25519 => &X25519,
            Self::Secp256R1 => &ECDH_P256,
            Self::Secp384R1 => &ECDH_P384,
        }
    }
}
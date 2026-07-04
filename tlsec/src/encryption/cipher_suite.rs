use ring::aead::{self, Aad, LessSafeKey, Nonce, Tag, UnboundKey};

use bytes::*;

use crate::error::*;

macro_rules! impl_cs {
    (
        $name:ident,
        $version:expr,
        $type:expr,
        $kl:expr,
        $nl:expr,
        $iv:expr,
        $salt:expr,
        $algo:expr
    ) => {
        pub struct $name {
            pub version: u16,
            pub typ: u16,
            pub key: [u8; $kl],
            pub iv: [u8; $iv],
            pub nonce: [u8; $nl],
            pub salt: [u8; $salt],
            pub rec_seq: u64,
            pub ring_key: LessSafeKey,
        }

        impl $name {
            pub fn new(key: [u8; $kl], nonce: [u8; $nl]) -> Self {
                let mut iv = [0u8; $iv];
                let mut salt = [0u8; $salt];

                if $salt > 0 {
                    salt.copy_from_slice(&nonce[0..$salt]);
                    iv.copy_from_slice(&nonce[$salt..$salt + $iv]);
                } else {
                    iv.copy_from_slice(&nonce[..$iv]);
                }

                let ring_key = LessSafeKey::new(
                    UnboundKey::new($algo, &key).unwrap()
                );

                Self {
                    version: $version,
                    typ: $type,
                    key,
                    iv,
                    nonce,
                    salt,
                    rec_seq: 0,
                    ring_key,
                }
            }

            pub fn encrypt(&mut self, ad: &[u8], data: &mut BytesMut) -> TlsResult<()> {
                self.build_nonce();

                let unbound = UnboundKey::new($algo, &self.key).map_err(|e| TlsError::Crypto(format!("invalid key: {e}")))?;
                let key = LessSafeKey::new(unbound);
                let nonce = Nonce::assume_unique_for_key(self.nonce);
                let aad = Aad::from(ad);
                
                let tag_len = $algo.tag_len();
                let plaintext_len = data.len();
                data.resize(plaintext_len + tag_len, 0);
                
                let tag = key.seal_in_place_separate_tag(nonce, aad, &mut data[..plaintext_len])
                    .map_err(|e| TlsError::Crypto(format!("encryption error: {e}")))?;
                data[plaintext_len..].copy_from_slice(tag.as_ref());

                self.rec_seq += 1;

                Ok(())
            }

            pub fn decrypt(&mut self, ad: &[u8], data: &mut BytesMut) -> TlsResult<()> {
                self.build_nonce();

                let unbound: UnboundKey = UnboundKey::new($algo, &self.key).map_err(|e| TlsError::Crypto(format!("invalid key: {e}")))?;
                let key: LessSafeKey = LessSafeKey::new(unbound);
                let nonce: Nonce = Nonce::assume_unique_for_key(self.nonce);
                let aad: Aad<&[u8]> = Aad::from(ad);
                
                let tag_len: usize = $algo.tag_len();
                if data.len() < tag_len {
                    return Err(TlsError::Crypto("data too short for tag".to_string()));
                }
                
                let ciphertext_len: usize = data.len() - tag_len;
                let tag_bytes: BytesMut = data.split_off(ciphertext_len);
                let tag: Tag = Tag::try_from(tag_bytes.as_ref()).map_err(|e| TlsError::Crypto(format!("wrong tag length: {e}")))?;
                
                let plaintext_len: usize = key.open_in_place_separate_tag(nonce, aad, tag, &mut data[..], 0..)
                    .map_err(|e| TlsError::Crypto(format!("decryption failed: {e}")))?
                    .len();
                
                data.truncate(plaintext_len);

                self.rec_seq += 1;
                
                Ok(())
            }

            fn build_nonce(&mut self) {
                let mut nonce: [u8; $nl] = self.nonce;
                let seq_bytes: [u8; 8] = self.rec_seq.to_le_bytes();
                for i in 0..8 {
                    nonce[$nl - 8 + i] ^= seq_bytes[i];
                }
                self.nonce = nonce
            }
        }
    };
}

impl_cs!(Aes128, 0x0303, 0x0001, 16, 12, 8, 4, &aead::AES_128_GCM);
impl_cs!(Aes256, 0x0303, 0x0002, 32, 12, 8, 4, &aead::AES_256_GCM);
impl_cs!(ChaCha20, 0x0303, 0x0003, 32, 12, 12, 0, &aead::CHACHA20_POLY1305);

pub enum AnyCipher {
    Aes128Gcm(Aes128),
    Aes256Gcm(Aes256),
    ChaCha20Poly1305(ChaCha20),
}

impl AnyCipher {
    pub fn sequence(&self) -> u64 {
        match self {
            AnyCipher::Aes128Gcm(cs) => cs.rec_seq,
            AnyCipher::Aes256Gcm(cs) => cs.rec_seq,
            AnyCipher::ChaCha20Poly1305(cs) => cs.rec_seq,
        }
    }

    pub fn encrypt(&mut self, buf: &mut BytesMut, ad: &[u8]) -> TlsResult<()> {
        match self {
            AnyCipher::Aes128Gcm(cs) => cs.encrypt(ad, buf),
            AnyCipher::Aes256Gcm(cs) => cs.encrypt(ad, buf),
            AnyCipher::ChaCha20Poly1305(cs) => cs.encrypt(ad, buf),
        }
    }

    pub fn decrypt(&mut self, buf: &mut BytesMut, ad: &[u8]) -> TlsResult<()> {
        match self {
            AnyCipher::ChaCha20Poly1305(cs) => cs.decrypt(ad, buf),
            AnyCipher::Aes128Gcm(cs) => cs.decrypt(ad, buf),
            AnyCipher::Aes256Gcm(cs) => cs.decrypt(ad, buf),
        }
    }

    pub fn key(&self) -> &[u8] {
        match self {
            AnyCipher::ChaCha20Poly1305(cs) => &cs.key,
            AnyCipher::Aes128Gcm(cs) => &cs.key,
            AnyCipher::Aes256Gcm(cs) => &cs.key,
        }
    }
}

#[cfg(test)]
mod cipher_test {

}
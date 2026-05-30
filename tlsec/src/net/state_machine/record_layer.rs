use crate::encryption::cipher_suite::AnyCipher;
use super::deframer::{OpaqueMessage, PlainMessage};
use crate::message::*;
use crate::error::Error;

#[derive(PartialEq)]
pub enum DirectionState {
    Invalid,
    Prepared,
    Active,
}

pub struct RecordLayer {
    pub encrypter: Option<AnyCipher>,
    pub decrypter: Option<AnyCipher>,
    pub write_seq: u64,
    pub read_seq: u64,
    pub encrypt_state: DirectionState,
    pub decrypt_state: DirectionState,
}

impl RecordLayer {
    pub fn new() -> Self {
        Self {
            encrypter: None,
            decrypter: None,
            write_seq: 0,
            read_seq: 0,
            encrypt_state: DirectionState::Invalid,
            decrypt_state: DirectionState::Invalid,
        }
    }
    
    pub fn prepare_encrypter(&mut self, cipher: AnyCipher) {
        self.encrypter = Some(cipher);
        self.encrypt_state = DirectionState::Prepared;
    }
    
    pub fn prepare_decrypter(&mut self, cipher: AnyCipher) {
        self.decrypter = Some(cipher);
        self.decrypt_state = DirectionState::Prepared;
    }
    
    pub fn start_encrypting(&mut self) {
        if self.encrypt_state == DirectionState::Prepared {
            self.encrypt_state = DirectionState::Active;
        }
    }
    
    pub fn start_decrypting(&mut self) {
        if self.decrypt_state == DirectionState::Prepared {
            self.decrypt_state = DirectionState::Active;
        }
    }
    
    pub fn decrypt_incoming(&mut self, msg: OpaqueMessage) -> Result<PlainMessage, Error> {
        match self.decrypt_state {
            DirectionState::Active => {
                let cipher: &mut AnyCipher = self.decrypter.as_mut().ok_or(Error::Crypto("no decrypter".to_string()))?;
                let ad: [u8; 13] = Self::build_ad(self.write_seq, msg.typ, msg.version as u16, msg.payload.len());

                let mut payload: bytes::BytesMut = msg.payload;
                cipher.decrypt(self.read_seq, &mut payload, &ad)?;

                self.read_seq += 1;
                
                Ok(PlainMessage {
                    typ: msg.typ,
                    version: msg.version,
                    payload,
                })
            }
            _ => {
                Ok(PlainMessage {
                    typ: msg.typ,
                    version: msg.version,
                    payload: msg.payload,
                })
            }
        }
    }
    
    pub fn encrypt_outgoing(&mut self, msg: PlainMessage) -> Result<OpaqueMessage, Error> {
        match self.encrypt_state {
            DirectionState::Active => {
                let cipher: &mut AnyCipher = self.encrypter.as_mut().ok_or(Error::Crypto("no encrypter".to_string()))?;
                let ad: [u8; 13] = Self::build_ad(self.write_seq, msg.typ, msg.version as u16, msg.payload.len());

                let mut payload: bytes::BytesMut = msg.payload;
                cipher.encrypt(self.write_seq, &mut payload, &ad)?;

                self.write_seq += 1;
                
                Ok(OpaqueMessage {
                    typ: msg.typ,
                    version: msg.version,
                    payload,
                })
            }
            _ => {
                Ok(OpaqueMessage {
                    typ: msg.typ,
                    version: msg.version,
                    payload: msg.payload,
                })
            }
        }
    }
    
    fn build_ad(seq: u64, typ: RecordType, version: u16, len: usize) -> [u8; 13] {
        let mut ad: [u8; 13] = [0u8; 13];
        ad[0..8].copy_from_slice(&seq.to_be_bytes());
        ad[8] = typ as u8;
        ad[9] = (version >> 8) as u8;
        ad[10] = version as u8;
        ad[11] = (len >> 8) as u8;
        ad[12] = len as u8;
        ad
    }
    
    pub fn wants_key_update(&self) -> bool {
        self.write_seq >= 0xffff_ffff_ffff_0000
    }
}
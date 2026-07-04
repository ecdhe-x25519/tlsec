use crate::encryption::{key_exchange::*, key_schedule::*};

use crate::encryption::transcript::TranscriptHash;
use crate::message::handshake::extensions::SupportedNamedGroup;
use crate::message::handshake::hello::SupportedCipherSuite;
use crate::net::configs::configs::PskIdentity;
use crate::net::connection::deframer::OuterMessage;
use crate::{
    encryption::cipher_suite::AnyCipher,
    message::{record::*, version::Version},
};

use crate::ktls::socket::KtlsSocket;

use crate::error::*;

use bytes::*;

use ring::agreement::{EphemeralPrivateKey, PublicKey};

#[derive(Debug)]
pub struct InnerMessage {
    pub(crate) typ: RecordType,
    pub(crate) version: Version,
    pub(crate) plaintext: BytesMut,
}

impl InnerMessage {
    pub fn new(typ: RecordType, plaintext: BytesMut) -> Self {
        Self { typ, version: Version::Tls13, plaintext }
    }
}

pub struct RecordLayer {
    pub(crate) encrypter: Option<AnyCipher>,
    pub(crate) encrypter_state: bool,
    pub(crate) decrypter: Option<AnyCipher>,
    pub(crate) decrypter_state: bool,
    pub(crate) out_buf: BytesMut,
    pub(crate) cipher_state: CipherState,
    pub(crate) fd: i32,
}

impl RecordLayer {
    pub fn new(capacity: usize, fd: i32, group: &SupportedNamedGroup) -> TlsResult<Self> {
        Ok(Self {
            encrypter: None,
            encrypter_state: false,
            decrypter: None,
            decrypter_state: false,
            out_buf: BytesMut::with_capacity(capacity),
            cipher_state: CipherState::new(group)?,
            fd,
        })
    }

    pub fn derive_hs_keys(
        &mut self,
        cipher_suite: &SupportedCipherSuite,
        transcript: &TranscriptHash,
        algo: &SupportedNamedGroup,
        enable: bool,
    ) -> TlsResult<()> {
        self.cipher_state.compute_shared_secret(algo)?;

        let shared_secret = self.cipher_state.shared_key.as_ref()
            .ok_or(TlsError::Alert(AlertDescription::InternalTlsError))?;

        let mut pre_shared_key: Option<Vec<u8>> = None;
        let psk = self.cipher_state.pre_shared_key.take();
        if psk.is_some() {
            pre_shared_key = Some(psk.unwrap().psk)
        }

        let hs_keys: HandshakeKeys = HandshakeKeys::derive_handshake_keys(
            cipher_suite,
            pre_shared_key,
            shared_secret,
            &transcript,
        )?;

        let client_key = hs_keys.client;
        let server_key = hs_keys.server;

        self.set_decrypter_state(Some(server_key), enable);
        self.set_encrypter_state(Some(client_key), enable);

        Ok(())
    }

    pub fn derive_ap_keys(
        &mut self,
        cipher_suite: &SupportedCipherSuite,
        enable: bool,
    ) -> TlsResult<()> {
        let shared_secret = self.cipher_state.shared_key.as_ref()
            .ok_or(TlsError::Alert(AlertDescription::InternalTlsError))?;

        let hs_keys: ApplicationKeys = ApplicationKeys::derive_application_keys(
            cipher_suite,
            shared_secret,
        )?;

        let client_key = hs_keys.client;
        let server_key = hs_keys.server;

        self.set_decrypter_state(Some(server_key), enable);
        self.set_encrypter_state(Some(client_key), enable);

        Ok(())
    }

    pub fn enable_ktls(&mut self) -> TlsResult<()> {
        let ap_keys = ApplicationKeys { client: self.encrypter.take().unwrap(), server: self.decrypter.take().unwrap() };
        let fd = self.fd;
        let sock = KtlsSocket::new(fd, ap_keys);
        sock.set_ktls_rx()?;
        sock.set_ktls_tx()?;

        Ok(())
    }

    fn set_decrypter_state(&mut self, key: Option<AnyCipher>, enable: bool) {
        self.decrypter = key;
        self.decrypter_state = enable
    }

    fn set_encrypter_state(&mut self, key: Option<AnyCipher>, enable: bool) {
        self.encrypter = key;
        self.encrypter_state = enable;
    }

    pub fn decrypt(&mut self, msg: OuterMessage) -> TlsResult<InnerMessage> {
        if self.decrypter_state {
            let cipher: &mut AnyCipher = self.decrypter.as_mut().ok_or(TlsError::Crypto("no decrypter".to_string()))?;
            let ad: [u8; 13] = Self::build_ad(cipher.sequence(), msg.typ, msg.version.into(), msg.ciphertext.len());

            let mut ciphertext = msg.ciphertext;
            cipher.decrypt(&mut ciphertext, &ad)?;

            let typ = RecordType::try_from(ciphertext.get_u8())?;
            let version = Version::try_from(ciphertext.get_u16())?;
            let len = ciphertext.get_u16() as usize;

            let plaintext = ciphertext.split_to(len);

            Ok(InnerMessage {
                typ,
                version,
                plaintext,
            })
        } else {
            Ok(InnerMessage {
                typ: msg.typ,
                version: msg.version,
                plaintext: msg.ciphertext,
            })
        }
    }

    pub fn encrypt(&mut self, msg: InnerMessage) -> TlsResult<OuterMessage> {
        if self.encrypter_state {
            if self.need_key_update() {
                return Err(TlsError::Alert(AlertDescription::InternalTlsError));
            }

            let cipher: &mut AnyCipher = self.encrypter.as_mut().ok_or(TlsError::Crypto("no encrypter".to_string()))?;
            let ad: [u8; 13] = Self::build_ad(cipher.sequence(), msg.typ, msg.version.into(), msg.plaintext.len());

            Record {
                record_type: RecordType::ApplicationData,
                legacy_version: Version::Tls13,
                payload: RecordPayload::ApplicationData(msg.plaintext.freeze()),
            }.encode(&mut self.out_buf);

            cipher.encrypt(&mut self.out_buf, &ad)?;

            Ok(OuterMessage {
                typ: msg.typ,
                version: msg.version,
                ciphertext: self.out_buf.split(),
            })
        } else {
            Ok(OuterMessage {
                typ: msg.typ,
                version: msg.version,
                ciphertext: msg.plaintext,
            })
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
    
    fn need_key_update(&self) -> bool {
        let cipher: &AnyCipher = &self.encrypter.as_ref().unwrap();
        cipher.sequence() >= 0xffff_ffff_ffff_0000
    }
}

pub struct CipherState {
    pub group: SupportedNamedGroup,
    pub private_key: Option<EphemeralPrivateKey>,
    pub public_key: Option<PublicKey>,
    pub peer_public_key: Option<Bytes>,
    pub shared_key: Option<Vec<u8>>,
    pub pre_shared_key: Option<PskIdentity>,
}

impl CipherState {
    pub fn new(group: &SupportedNamedGroup) -> TlsResult<Self> {
        let (privkey, pubkey) = generate_key_pair(group)?;

        Ok(Self {
            group: *group,
            private_key: Some(privkey),
            public_key: Some(pubkey),
            peer_public_key: None,
            shared_key: None,
            pre_shared_key: None,
        })
    }

    pub fn compute_shared_secret(&mut self, group: &SupportedNamedGroup) -> TlsResult<()> {
        let privkey = self.private_key.take().unwrap();

        let peer_pubkey = self.peer_public_key.as_ref()
            .ok_or(TlsError::Alert(AlertDescription::HandshakeFailure))?;
        
        let sc = compute_shared_secret(privkey, peer_pubkey, group)?;
        self.shared_key = Some(sc);

        Ok(())
    }
}
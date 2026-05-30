use crate::message::*;
use crate::error::*;

use bytes::*;

pub struct ClientHelloPayload {
    pub legacy_version: Version,
    pub random: [u8; 32],
    pub legacy_session_id: Bytes, // length = u8
    pub cipher_suites: Vec<CipherSuite>, // length = u16
    pub legacy_compression_methods: Vec<CompressionMethod>, // length = u8
    pub extensions: Vec<Extension>, // length = u16
}

impl Serialize for ClientHelloPayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.legacy_version as u16);
        buf.put_slice(&self.random);

        buf.put_u8(self.legacy_session_id.len() as u8);
        buf.put_slice(&self.legacy_session_id);

        buf.put_u16((self.cipher_suites.len() * 2) as u16);
        for cs in &self.cipher_suites {
            buf.put_u16(*cs as u16);
        }

        buf.put_u8(self.legacy_compression_methods.len() as u8);
        for cm in &self.legacy_compression_methods {
            buf.put_u8(*cm as u8);
        }

        let ext_len_pos: usize = buf.len();
        buf.put_u16(0);

        for ext in &self.extensions {
            ext.encode(buf);
        }

        let ext_len: u16 = (buf.len() - ext_len_pos - 2) as u16;
        buf[ext_len_pos..ext_len_pos+2].copy_from_slice(&ext_len.to_be_bytes());
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let legacy_version: Version = Version::try_from(buf.get_u16())?;

        if buf.remaining() < 32 {
            return Err(Error::Incomplete(32 - buf.remaining()));
        }

        let mut random_bytes: [u8; 32] = [0u8; 32];
        buf.copy_to_slice(&mut random_bytes);
        let random: [u8; 32] = random_bytes;

        if buf.remaining() < 1 {
            return Err(Error::Incomplete(1 - buf.remaining()));
        }

        let legacy_session_id_length: usize = buf.get_u8() as usize;

        if legacy_session_id_length > 32 {
            return Err(Error::Alert(AlertDescription::HandshakeFailure));
        } else if buf.remaining() < legacy_session_id_length {
            return Err(Error::Incomplete(legacy_session_id_length - buf.remaining()));
        }

        let legacy_session_id: Bytes = buf.split_to(legacy_session_id_length).freeze();

        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let cipher_suites_length: usize = buf.get_u16() as usize;

        if buf.remaining() < cipher_suites_length {
            return Err(Error::Incomplete(cipher_suites_length - buf.remaining()));
        }

        let mut cipher_suites: Vec<CipherSuite> = Vec::new();
        for _ in 0..cipher_suites_length / 2 {
            cipher_suites.push(CipherSuite::try_from(buf.get_u16())?);
        }

        if buf.remaining() < 1 {
            return Err(Error::Incomplete(1 - buf.remaining()));
        }

        let legacy_compression_methods_length: usize = buf.get_u8() as usize;

        if buf.remaining() < legacy_compression_methods_length {
            return Err(Error::Incomplete(legacy_compression_methods_length - buf.remaining()));
        }

        let mut legacy_compression_methods: Vec<CompressionMethod> = Vec::new();
        for _ in 0..legacy_compression_methods_length {
            legacy_compression_methods.push(CompressionMethod::try_from(buf.get_u8())?);
        }

        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let extensions_length: usize = buf.get_u16() as usize;

        if buf.remaining() < extensions_length {
            return Err(Error::Incomplete(extensions_length - buf.remaining()));
        }

        let mut exts: BytesMut = buf.split_to(extensions_length);
        let mut extensions: Vec<Extension> = Vec::new();
        while exts.remaining() > 0 {
            extensions.push(Extension::decode(&mut exts)?);
        }

        Ok(Self {
            legacy_version,
            random,
            legacy_session_id,
            cipher_suites,
            legacy_compression_methods,
            extensions,
        })
    }
}

#[cfg(test)]
mod test_client_hello_parse {
    
}
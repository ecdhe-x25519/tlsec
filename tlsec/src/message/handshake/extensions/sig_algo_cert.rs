use crate::message::serialize::Serialize;
use crate::message::handshake::extensions::SignatureScheme;

use crate::error::*;

use bytes::*;

use brevno::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureAlgorithmsCertPayload {
    pub schemes: Vec<SignatureScheme>, // length u16
}

impl Serialize for SignatureAlgorithmsCertPayload {
    fn encode(&self, buf: &mut BytesMut) {
        let sc_len_pos: usize = buf.len();
        buf.put_u16(0);

        for sc in &self.schemes {
            buf.put_u16((*sc).into());
        }

        let sc_len: u16 = (buf.len() - sc_len_pos - 2) as u16;
        buf[sc_len_pos..sc_len_pos+2].copy_from_slice(&sc_len.to_be_bytes());
    }

    fn decode(buf: &mut BytesMut) -> TlsResult<Self> {
        if buf.remaining() < 2 {
            error!(format!("Incomplete data: need {} more bytes", (2 - buf.remaining())));
            return Err(TlsError::Incomplete(2 - buf.remaining()));
        }

        let length: usize = buf.get_u16() as usize;

        if buf.remaining() < length {
            error!(format!("Incomplete data: need {} more bytes", (length - buf.remaining())));
            return Err(TlsError::Incomplete(length - buf.remaining()));
        }

        let mut schemes = Vec::new();
        for _ in 0..length / 2 {
            schemes.push(SignatureScheme::try_from(buf.get_u16())?);
        }

        Ok(Self {
            schemes
        })
    }
}

#[cfg(test)]
mod test_sig_algo_cert_parse {
    
}
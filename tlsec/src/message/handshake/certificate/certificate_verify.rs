use crate::message::*;
use crate::error::*;

use bytes::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateVerifyPayload {
    pub algorithm: SignatureScheme,
    pub signature: Bytes, // length u16
}

impl Serialize for CertificateVerifyPayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.algorithm as u16);
        buf.put_u16(self.signature.len() as u16);
        buf.put_slice(&self.signature);
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let algorithm: SignatureScheme = SignatureScheme::try_from(buf.get_u16())?;

        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let length: usize = buf.get_u16() as usize;

        if buf.remaining() < length {
            return Err(Error::Incomplete(length - buf.remaining()));
        }

        let signature: Bytes = buf.split_to(length).freeze();

        Ok(Self {
            algorithm,
            signature,
        })
    }
}

#[cfg(test)]
mod test_cert_verify_parse {
    
}
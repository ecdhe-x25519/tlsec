use crate::message::handshake::extensions::SignatureScheme;
use crate::message::serialize::Serialize;

use crate::error::*;

use bytes::*;

use brevno::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateVerifyPayload {
    pub algorithm: SignatureScheme,
    pub signature: Bytes, // length u16
}

impl Serialize for CertificateVerifyPayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.algorithm.into());
        buf.put_u16(self.signature.len() as u16);
        buf.put_slice(&self.signature);
    }

    fn decode(buf: &mut BytesMut) -> TlsResult<Self> {
        if buf.remaining() < 4 {
            error!(format!("Incomplete data: need {} more bytes", (4 - buf.remaining())));
            return Err(TlsError::Incomplete(4 - buf.remaining()));
        }

        let algorithm: SignatureScheme = SignatureScheme::try_from(buf.get_u16())?;

        let length: usize = buf.get_u16() as usize;

        if buf.remaining() < length {
            error!(format!("Incomplete data: need {} more bytes", (length - buf.remaining())));
            return Err(TlsError::Incomplete(length - buf.remaining()));
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
    use super::*;

    #[test]
    fn cert_verify_parse() {
        let mut buf: BytesMut = BytesMut::new();

        let sig: Bytes = Bytes::new();

        let cert_verify: CertificateVerifyPayload = CertificateVerifyPayload {
            algorithm: SignatureScheme::Ed25519,
            signature: sig,
        };

        cert_verify.encode(&mut buf);

        let decoded: CertificateVerifyPayload = CertificateVerifyPayload::decode(&mut buf).unwrap();

        assert_eq!(cert_verify, decoded);
    }
}
use crate::{error::*, message::{handshake::extensions::*, serialize::Serialize}};

use bytes::*;

use brevno::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressedCertificatePayload {
    pub algorithm: CompressionAlgorithm,
    pub uncompressed_length: [u8; 3],
    pub compressed_data: Bytes, // 3 bytes len + data
}

impl Serialize for CompressedCertificatePayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.algorithm.into());

        buf.put_slice(&self.uncompressed_length);

        let list_len_pos: usize = buf.len();
        buf.put_slice(&[0u8; 3]);

        buf.put(self.compressed_data.as_ref());

        let list_len: u32 = (buf.len() - list_len_pos - 3) as u32;
        let len_bytes: [u8; _] = list_len.to_be_bytes();
        buf[list_len_pos..list_len_pos+3].copy_from_slice(&len_bytes[1..]);
    }

    fn decode(buf: &mut BytesMut) -> TlsResult<Self> {
        if buf.remaining() < 7 {
            error!(format!("Incomplete data: need {} more bytes", (7 - buf.remaining())));
            return Err(TlsError::Incomplete(7 - buf.remaining()));
        }

        let algorithm = CompressionAlgorithm::try_from(buf.get_u8())?;

        let uncompressed_length: [u8; 3] = [buf.get_u8(), buf.get_u8(), buf.get_u8()];

        let length: [u8; 3] = [buf.get_u8(), buf.get_u8(), buf.get_u8()];
        let certificate_length: usize = u32::from_be_bytes([0,
            length[0],
            length[1],
            length[2]
        ]) as usize;

        if buf.remaining() < certificate_length {
            error!(format!("Incomplete data: need {} more bytes", (certificate_length - buf.remaining())));
            return Err(TlsError::Incomplete(certificate_length - buf.remaining()));
        }

        let compressed_data = buf.split_to(certificate_length).freeze();

        Ok(Self {
            algorithm,
            uncompressed_length,
            compressed_data,
        })
    }
}
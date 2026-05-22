use super::*;
use super::extensions::*;

pub struct CertificateEntry {
    pub certificate_data: BytesMut, // length = 3 bytes
    pub extensions: Vec<Extension>, // length = u16
}

impl Serialize for CertificateEntry {
    fn encode(&self, buf: &mut BytesMut) {
        let cert_len: u32 = self.certificate_data.len() as u32;
        let len_bytes: [u8; _] = cert_len.to_be_bytes();
        buf.put_slice(&len_bytes[1..]);
        
        buf.put_slice(&self.certificate_data);
        
        let ext_len_pos: usize = buf.len();
        buf.put_u16(0);
        for ext in &self.extensions {
            ext.encode(buf);
        }
        let ext_len: u16 = (buf.len() - ext_len_pos - 2) as u16;
        buf[ext_len_pos..ext_len_pos+2].copy_from_slice(&ext_len.to_be_bytes());
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 3 {
            return Err(Error::Incomplete(3 - buf.remaining()));
        }

        let len_bytes: [u8; 3] = [buf.get_u8(), buf.get_u8(), buf.get_u8()];
        let cert_len: usize = u32::from_be_bytes([0, len_bytes[0], len_bytes[1], len_bytes[2]]) as usize;

        if buf.remaining() < cert_len {
            return Err(Error::Incomplete(cert_len - buf.remaining()));
        }
        let certificate_data: BytesMut = buf.split_to(cert_len);

        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let ext_len: usize = buf.get_u16() as usize;
        if buf.remaining() < ext_len {
            return Err(Error::Incomplete(ext_len - buf.remaining()));
        }

        let mut ext_buf: BytesMut = buf.split_to(ext_len);
        let mut extensions: Vec<Extension> = Vec::new();
        while ext_buf.remaining() > 0 {
            extensions.push(Extension::decode(&mut ext_buf)?);
        }

        Ok(CertificateEntry {
            certificate_data,
            extensions,
        })
    }
}

pub struct CertificatePayload {
    pub certificate_request_context: BytesMut, // length = u8
    pub certificate_list: Vec<CertificateEntry>, // length = 3 bytes
}

impl Serialize for CertificatePayload {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.certificate_request_context.len() as u8);
        buf.put_slice(&self.certificate_request_context);

        let list_len_pos: usize = buf.len();
        buf.put_slice(&[0u8; 3]);
        
        for cert in &self.certificate_list {
            cert.encode(buf);
        }

        let list_len: u32 = (buf.len() - list_len_pos - 3) as u32;
        let len_bytes: [u8; _] = list_len.to_be_bytes();
        buf[list_len_pos..list_len_pos+3].copy_from_slice(&len_bytes[1..]);
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 1 {
            return Err(Error::Incomplete(1 - buf.remaining()));
        }

        let certificate_request_context_length: usize = buf.get_u8() as usize;

        if buf.remaining() < certificate_request_context_length {
            return Err(Error::Incomplete(certificate_request_context_length - buf.remaining()));
        }

        let certificate_request_context: BytesMut = buf.split_to(certificate_request_context_length);

        if buf.remaining() < 3 {
            return Err(Error::Incomplete(3 - buf.remaining()));
        }

        let len_bytes: [u8; 3] = [buf.get_u8(), buf.get_u8(), buf.get_u8()];
        let certificate_list_length: usize = u32::from_be_bytes([0, len_bytes[0], len_bytes[1], len_bytes[2]]) as usize;

        if buf.remaining() < certificate_list_length {
            return Err(Error::Incomplete(certificate_list_length - buf.remaining()));
        }

        let mut list_buf: BytesMut = buf.split_to(certificate_list_length);
        let mut certificate_list: Vec<CertificateEntry> = Vec::new();
        while list_buf.remaining() > 0 {
            certificate_list.push(CertificateEntry::decode(&mut list_buf)?);
        }

        Ok(Self {
            certificate_request_context,
            certificate_list,
        })
    }
}

pub struct CertificateVerifyPayload {
    pub algorithm: SignatureScheme,
    pub signature: BytesMut, // length = u16
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

        let signature_length: usize = buf.get_u16() as usize;

        if buf.remaining() < signature_length {
            return Err(Error::Incomplete(signature_length - buf.remaining()));
        }

        let signature: BytesMut = buf.split_to(signature_length);

        Ok(Self {
            algorithm,
            signature,
        })
    }
}
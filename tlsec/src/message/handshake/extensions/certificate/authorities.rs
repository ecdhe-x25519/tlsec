use crate::message::*;
use crate::error::*;

use bytes::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateAuthoritiesPayload {
    pub authorities: Vec<Bytes>, // length u16
}

impl Serialize for CertificateAuthoritiesPayload {
    fn encode(&self, buf: &mut BytesMut) {
        let len_pos: usize = buf.len();
        buf.put_u16(0);

        for auth in &self.authorities {
            buf.put_u16(auth.len() as u16);
            buf.put_slice(auth);
        }

        let auth_len: u16 = (buf.len() - len_pos - 2) as u16;
        buf[len_pos..len_pos+2].copy_from_slice(&auth_len.to_be_bytes());
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let len: usize = buf.get_u16() as usize;
        if buf.remaining() < len {
            return Err(Error::Incomplete(len - buf.remaining()));
        }

        let mut data: BytesMut = buf.split_to(len);
        let mut authorities: Vec<Bytes> = Vec::new();
        
        while data.remaining() > 0 {
            if data.remaining() < 2 {
                return Err(Error::Incomplete(2 - data.remaining()));
            }
            
            let auth_len: usize = data.get_u16() as usize;
            if data.remaining() < auth_len {
                return Err(Error::Incomplete(auth_len - data.remaining()));
            }
            
            let auth = data.split_to(auth_len).freeze();
            authorities.push(auth);
        }

        Ok(CertificateAuthoritiesPayload { authorities })
    }
}

#[cfg(test)]
mod test_ca_auth_parse {
    
}
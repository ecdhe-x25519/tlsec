use crate::message::*;
use crate::error::*;

use bytes::*;

pub struct KeyShareClient {
    pub client_shares: Vec<KeyShareEntry>, // length = u16
}

impl Serialize for KeyShareClient {
    fn encode(&self, buf: &mut BytesMut) {
        let mut inner: BytesMut = BytesMut::new();
        for share in &self.client_shares {
            share.encode(&mut inner);
        }
        buf.put_u16(inner.len() as u16);
        buf.put_slice(&inner);
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let list_length: usize = buf.get_u16() as usize;

        if buf.remaining() < list_length {
            return Err(Error::Incomplete(list_length - buf.remaining()));
        }

        let mut data: BytesMut = buf.split_to(list_length);

        let mut client_shares: Vec<KeyShareEntry> = Vec::new();

        while data.has_remaining() {
            client_shares.push(KeyShareEntry::decode(&mut data)?);
        }

        Ok(Self { client_shares })
    }
}

#[cfg(test)]
mod test_client_ks_parse {
    
}
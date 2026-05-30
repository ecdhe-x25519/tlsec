use crate::message::*;
use crate::error::*;

use bytes::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidFiltersPayload {
    pub filters: Vec<OidFilter>, // length u16
}

impl Serialize for OidFiltersPayload {
    fn encode(&self, buf: &mut BytesMut) {
        let oid_len_pos: usize = buf.len();
        buf.put_u16(0);

        for oid in &self.filters {
            oid.encode(buf);
        }

        let oid_len: u16 = (buf.len() - oid_len_pos - 2) as u16;
        buf[oid_len_pos..oid_len_pos+2].copy_from_slice(&oid_len.to_be_bytes());
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let length: usize = buf.get_u16() as usize;

        if buf.remaining() < length {
            return Err(Error::Incomplete(length - buf.remaining()));
        }

        let mut xyu: BytesMut = buf.split_to(length);
        let mut filters: Vec<OidFilter> = Vec::new();
        while xyu.remaining() > 0 {
            filters.push(OidFilter::decode(&mut xyu)?);
        }

        Ok(Self {
            filters
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidFilter {
    pub oid: Bytes, // length u16
    pub value: Bytes, // length u16
}

impl Serialize for OidFilter {
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.oid.len() as u16);
        buf.put(self.oid.as_ref());

        buf.put_u16(self.value.len() as u16);
        buf.put(self.value.as_ref());
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let oid_length: usize = buf.get_u16() as usize;

        if buf.remaining() < oid_length {
            return Err(Error::Incomplete(oid_length - buf.remaining()));
        }

        let oid: Bytes = buf.split_to(oid_length).freeze();

        if buf.remaining() < 2 {
            return Err(Error::Incomplete(2 - buf.remaining()));
        }

        let value_length: usize = buf.get_u16() as usize;

        if buf.remaining() < value_length {
            return Err(Error::Incomplete(value_length - buf.remaining()));
        }

        let value: Bytes = buf.split_to(value_length).freeze();

        Ok(Self {
            oid,
            value,
        })
    }
}

#[cfg(test)]
mod test_oid_filter_parse {
    
}
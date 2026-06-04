use crate::message::serialize::Serialize;

use crate::error::Error;

use bytes::*;

#[derive(Debug, PartialEq, Eq)]
pub struct AlpnPayload {
    pub protocols: Vec<AlpnProtocol>, // length = u16
}

impl Serialize for AlpnPayload {
    fn encode(&self, buf: &mut BytesMut) {
        let mut inner: BytesMut = BytesMut::new();
        for proto in &self.protocols {
            proto.encode(&mut inner);
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

        let mut protocols: Vec<AlpnProtocol> = Vec::new();

        while data.has_remaining() {
            protocols.push(AlpnProtocol::decode(&mut data)?);
        }

        Ok(Self { protocols })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct AlpnProtocol {
    pub name: AlpnProtocols, // length = u8
}

impl Serialize for AlpnProtocol {
    fn encode(&self, buf: &mut BytesMut) {
        let proto_bytes = match self.name {
            AlpnProtocols::Http11 => b"http/1.1" as &[u8],
            AlpnProtocols::H2 => b"h2" as &[u8],
            AlpnProtocols::H3 => b"h3" as &[u8],
        };
        buf.put_u8(proto_bytes.len() as u8);
        buf.put_slice(proto_bytes);
    }

    fn decode(buf: &mut BytesMut) -> Result<Self, Error> {
        if buf.remaining() < 1 {
            return Err(Error::Incomplete(1 - buf.remaining()));
        }

        let len: usize = buf.get_u8() as usize;

        if buf.remaining() < len {
            return Err(Error::Incomplete(len - buf.remaining()));
        }

        let name: AlpnProtocols = AlpnProtocols::try_from(buf.split_to(len))?;

        Ok(Self { name })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlpnProtocols {
    Http11,
    H2,
    H3,
}

impl TryFrom<BytesMut> for AlpnProtocols {
    type Error = Error;

    fn try_from(value: BytesMut) -> Result<Self, Self::Error> {
        match value.as_ref() {
            b"http/1.1" => Ok(AlpnProtocols::Http11),
            b"h2" => Ok(AlpnProtocols::H2),
            b"h3" => Ok(AlpnProtocols::H3),
            _ => Err(Error::Unknown("ALPN protocol")),
        }
    }
}

impl AsRef<[u8]> for AlpnProtocols {
    fn as_ref(&self) -> &[u8] {
        match self {
            AlpnProtocols::Http11 => b"http/1.1",
            AlpnProtocols::H2 => b"h2",
            AlpnProtocols::H3 => b"h3",
        }
    }
}

#[cfg(test)]
mod test_alpn_parse {
    
}
use crate::message::serialize::Serialize;
use crate::message::version::Version;
use crate::message::alert::AlertPayload;
use crate::message::handshake::hello::*;
use crate::message::handshake::messages::HandshakeMessage;

use crate::error::*;

use bytes::*;

use brevno::*;

#[derive(Debug, PartialEq, Eq)]
pub struct Record {
    pub record_type: RecordType,
    pub legacy_version: Version,
    pub payload: RecordPayload, // length = u16
}

impl Record {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.record_type as u8);
        buf.put_u16(self.legacy_version.into());

        let len_pos: usize = buf.len();
        buf.put_u16(0);

        self.payload.encode_payload(buf);

        let len: u16 = (buf.len() - len_pos - 2) as u16;
        buf[len_pos..len_pos+2].copy_from_slice(&len.to_be_bytes());
    }

    pub fn decode(buf: &mut BytesMut, cipher_suite: Option<&SupportedCipherSuite>) -> TlsResult<Self> {
        if buf.remaining() < 5 {
            error!(format!("Incomplete data: need {} more bytes", (1 - buf.remaining())));
            return Err(TlsError::Incomplete(1 - buf.remaining()));
        }
        
        let record_type: RecordType = RecordType::try_from(buf.get_u8())?;

        let legacy_version: Version = Version::try_from(buf.get_u16())?;

        let length: usize = buf.get_u16() as usize;
        
        if buf.remaining() < length {
            error!(format!("Incomplete data: need {} more bytes", (length - buf.remaining())));
            return Err(TlsError::Incomplete(length - buf.remaining()));
        }

        let mut payload_buf: BytesMut = buf.split_to(length);
        let payload: RecordPayload = RecordPayload::decode_payload(record_type, &mut payload_buf, cipher_suite)?;
        
        Ok(Self {
            record_type,
            legacy_version,
            payload,
        })
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    Alert = 0x15,
    HandshakeMessage = 0x16,
    ApplicationData = 0x17,
}

impl TryFrom<u8> for RecordType {
    type Error = TlsError;

    fn try_from(value: u8) -> TlsResult<Self> {
        match value {
            0x15 => Ok(Self::Alert),
            0x16 => Ok(Self::HandshakeMessage),
            0x17 => Ok(Self::ApplicationData),
            _ => Err(TlsError::Unknown("record type")),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RecordPayload {
    Handshake(Vec<HandshakeMessage>),
    Alert(AlertPayload),
    ApplicationData(Bytes),
}

impl RecordPayload {
    pub fn encode_payload(&self, buf: &mut BytesMut) {
        match self {
            Self::Handshake(msgs) => {
                for msg in msgs {
                    msg.encode(buf);
                }
            }
            Self::Alert(alert) => {
                alert.encode(buf);
            }
            Self::ApplicationData(data) => {
                buf.put_slice(data);
            }
        }
    }

    pub fn decode_payload(record_type: RecordType, buf: &mut BytesMut, cipher_suite: Option<&SupportedCipherSuite>) -> TlsResult<Self> {
        match record_type {
            RecordType::HandshakeMessage => {
                let mut msgs: Vec<HandshakeMessage> = Vec::new();
                while buf.has_remaining() {
                    msgs.push(HandshakeMessage::decode(buf, cipher_suite)?);
                }
                Ok(RecordPayload::Handshake(msgs))
            }
            RecordType::Alert => {
                Ok(RecordPayload::Alert(AlertPayload::decode(buf)?))
            }
            RecordType::ApplicationData => {
                Ok(RecordPayload::ApplicationData(buf.split().freeze()))
            }
        }
    }
}

#[cfg(test)]
mod test_record_parse {
    use super::*;

    #[test]
    fn record_parse() {
        let mut buf: BytesMut = BytesMut::new();

        let app_data: Bytes = Bytes::new();

        let rec: Record = Record {
            record_type: RecordType::ApplicationData,
            legacy_version: Version::Tls12,
            payload: RecordPayload::ApplicationData(app_data),
        };

        rec.encode(&mut buf);

        let decoded: Record = Record::decode(&mut buf, Some(&SupportedCipherSuite::ChaCha20)).unwrap();

        assert_eq!(rec, decoded);
    }
}
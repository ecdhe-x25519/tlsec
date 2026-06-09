use crate::error::*;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    Tls10 = 0x0301,
    Tls11 = 0x0302,
    Tls12 = 0x0303,
    Tls13 = 0x0304,
}

impl TryFrom<u16> for Version {
    type Error = TlsError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0301 => Ok(Self::Tls10),
            0x0302 => Ok(Self::Tls11),
            0x0303 => Ok(Self::Tls12),
            0x0304 => Ok(Self::Tls13),
            _ => Err(TlsError::Unknown("version")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedVersion {
    Tls13,
}

impl SupportedVersion {
    pub fn compare(self, version: &Version) -> Option<SupportedVersion> {
        match version {
            Version::Tls13 => Some(Self::Tls13),
            _ => None,
        }
    }
}
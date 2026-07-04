use crate::error::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    Tls10,
    Tls11,
    Tls12,
    Tls13,
    Unknown(u16),
}

impl Version {
    pub(crate) fn to_supported(&self) -> Option<SupportedVersion> {
        match self {
            Version::Tls13 => Some(SupportedVersion::Tls13),
            _ => None,
        }
    }
}

impl Into<u16> for Version {
    fn into(self) -> u16 {
        match self {
            Self::Tls10 => 0x0301,
            Self::Tls11 => 0x0302,
            Self::Tls12 => 0x0303,
            Self::Tls13 => 0x0304,
            Self::Unknown(u) => u,
        }
    }
}

impl TryFrom<u16> for Version {
    type Error = TlsError;

    fn try_from(value: u16) -> TlsResult<Self> {
        match value {
            0x0301 => Ok(Self::Tls10),
            0x0302 => Ok(Self::Tls11),
            0x0303 => Ok(Self::Tls12),
            0x0304 => Ok(Self::Tls13),
            _ => {
                Ok(Self::Unknown(value))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedVersion {
    Tls13,
}

impl SupportedVersion {
    pub(crate) fn to_unsupported(&self) -> Version {
        match self {
            Self::Tls13 => Version::Tls13,
        }
    }
}
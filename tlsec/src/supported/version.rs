use crate::messages::Version;

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
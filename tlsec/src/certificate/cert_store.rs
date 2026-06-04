use std::fs;

use crate::error::*;

use pem::{Pem, parse_many};

pub struct Der {
    pub cert: Vec<u8>,
}

pub struct CertStore {
    pub certs: Vec<Der>,
}

impl CertStore {
    pub fn parse_root_certs(root_dir: &str) -> Result<CertStore, Error> {
        let mut certs: Vec<Der> = Vec::new();

        for entry in fs::read_dir(root_dir).map_err(|e| Error::Io(format!("read directory error: {e}")))? {
            let entry = entry
                .map_err(|e| Error::Io(format!("read entry error: {e}")))?;
            let path = entry.path();

            if !path.is_file() && !path.ends_with("pem") {
                continue;
            }

            let data: Vec<u8> = fs::read(&path)
                .map_err(|e| Error::Io(format!("read file error: {e}")))?;

            if let Ok(pems) = parse_many(&data) {
                for pem in pems {
                    if pem.tag() == "CERTIFICATE" {
                        let cert: Vec<u8> = pem.contents().to_vec();
                        certs.push(Der{cert});
                    }
                }
            }
        }

        Ok(CertStore{certs})
    }

    pub fn parse_third_party_pem(path: &str) -> Result<Der, Error> {
        let cert_string: String = fs::read_to_string(path)
            .map_err(|e| Error::Io(format!("certificate read error: {e}")))?;

        let pem_chain: Vec<Pem> = parse_many(cert_string)
            .map_err(|e| Error::Io(format!("PEM parsing error: {e}")))?;

        let pem: &Pem = &pem_chain[0];

        if pem.tag() != "CERTIFICATE" {
            return Err(Error::Io("PEM tag missing".to_string()));
        }

        let cert: Vec<u8> = pem.contents().to_vec();

        Ok(Der{cert})
    }

}

#[cfg(test)]
mod test_cert_parse {
    
}
use std::fs;

use pem::{Pem, parse_many};

use super::*;

pub fn parse_root_certs(root_dir: &str) -> Result<Vec<Der>, Error> {
    let mut certs: Vec<Der> = Vec::new();
    
    for entry in fs::read_dir(root_dir).map_err(|e| Error::Io(format!("read directory error: {e}")))? {
        let entry = entry.map_err(|e| Error::Io(format!("read entry error: {e}")))?;
        let path = entry.path();
        
        if !path.is_file() {
            continue;
        }
        
        let data = fs::read(&path).map_err(|e| Error::Io(format!("read file error: {e}")))?;
        
        if let Ok(pems) = parse_many(&data) {
            for pem in pems {
                if pem.tag() == "CERTIFICATE" {
                    certs.push(pem.contents().to_vec().into());
                }
            }
        }
    }
    
    Ok(certs)
}

pub fn parse_pem(path: &str) -> Result<Der, Error> {
    let cert_string: String = fs::read_to_string(path)
        .map_err(|e| Error::Io(format!("certificate read error: {e}")))?;

    let pem_chain: Vec<Pem> = parse_many(cert_string)
        .map_err(|e| Error::Io(format!("PEM parsing error: {e}")))?;

    let pem: &Pem = &pem_chain[0];

    if pem.tag() != "CERTIFICATE" {
        return Err(Error::Io("PEM tag missing".to_string()));
    }

    Ok(Der(pem.contents().to_vec()))
}
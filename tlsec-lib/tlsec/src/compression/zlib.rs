use std::io::Read;

use crate::certificate::Der;

use super::Error;

use flate2::read::{ZlibEncoder, ZlibDecoder};
use flate2::Compression;

pub fn zlib_rs_compress_cert(cert: &Der) -> Result<Vec<u8>, Error> {
    let mut encoder = ZlibEncoder::new(cert.0.as_slice(), Compression::fast());
    let mut compressed = Vec::new();
    encoder.read_to_end(&mut compressed)
        .map_err(|e| Error::Io(format!("zlib compression error: {}", e)))?;
    Ok(compressed)
}

pub fn zlib_rs_decompress_cert(compressed: &[u8]) -> Result<Der, Error> {
    let mut decoder = ZlibDecoder::new(compressed);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)
        .map_err(|e| Error::Io(format!("zlib decompression error: {}", e)))?;
    Ok(Der(decompressed))
}
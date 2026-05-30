use std::io::Read;

use crate::error::Error;

use flate2::read::{ZlibEncoder, ZlibDecoder};
use flate2::Compression;

pub fn zlib_rs_compress_cert(cert: &[u8]) -> Result<Vec<u8>, Error> {
    let mut encoder: ZlibEncoder<&[u8]> = ZlibEncoder::new(cert, Compression::fast());
    let mut compressed: Vec<u8> = Vec::new();
    encoder.read_to_end(&mut compressed)
        .map_err(|e| Error::Io(format!("zlib compression error: {}", e)))?;
    Ok(compressed)
}

pub fn zlib_rs_decompress_cert(compressed: &[u8]) -> Result<Vec<u8>, Error> {
    let mut decoder: ZlibDecoder<&[u8]> = ZlibDecoder::new(compressed);
    let mut decompressed: Vec<u8> = Vec::new();
    decoder.read_to_end(&mut decompressed)
        .map_err(|e| Error::Io(format!("zlib decompression error: {}", e)))?;
    Ok(decompressed)
}

#[cfg(test)]
mod test_zlib {
    
}
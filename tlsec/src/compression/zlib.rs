use std::io::Read;

use crate::error::TlsError;

use flate2::read::{ZlibEncoder, ZlibDecoder};
use flate2::Compression;

pub fn zlib_compress_cert(cert: &[u8]) -> Result<Vec<u8>, TlsError> {
    let mut encoder: ZlibEncoder<&[u8]> = ZlibEncoder::new(cert, Compression::fast());
    let mut compressed: Vec<u8> = Vec::new();
    encoder.read_to_end(&mut compressed)
        .map_err(|e| TlsError::Io(format!("zlib compression error: {}", e)))?;
    Ok(compressed)
}

pub fn zlib_decompress_cert(compressed_cert: &[u8]) -> Result<Vec<u8>, TlsError> {
    let mut decoder: ZlibDecoder<&[u8]> = ZlibDecoder::new(compressed_cert);
    let mut decompressed: Vec<u8> = Vec::new();
    decoder.read_to_end(&mut decompressed)
        .map_err(|e| TlsError::Io(format!("zlib decompression error: {}", e)))?;
    Ok(decompressed)
}

#[cfg(test)]
mod test_zlib {
    use crate::compression::zlib::{zlib_compress_cert, zlib_decompress_cert};
    use crate::encryption::random::Random;

    #[test]
    fn test_zlib_compress() {
        let rng: Random = Random::new();

        let mut cert: Vec<u8> = vec![0u8; 1500];
        rng.ochkagen(&mut cert).unwrap();

        let compressed_cert: Vec<u8> = zlib_compress_cert(&cert).unwrap();
        let decompressed_cert: Vec<u8> = zlib_decompress_cert(&compressed_cert).unwrap();

        assert_eq!(cert, decompressed_cert);
    }
}
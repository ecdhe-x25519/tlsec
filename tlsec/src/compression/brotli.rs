use std::io::Read;

use brotli::{CompressorReader, Decompressor};

use crate::error::Error;

pub fn brotli_compress_cert(cert: &[u8]) -> Result<Vec<u8>, Error> {
    let mut compressor: CompressorReader<&[u8]> = CompressorReader::new(cert, 4096, 5, 18);
    let mut compressed: Vec<u8> = Vec::new();
    compressor.read_to_end(&mut compressed).map_err(|e| Error::Io(format!("brotli compression error: {e}")))?;
    Ok(compressed)
}

pub fn brotli_decompress_cert(compressed_cert: &[u8]) -> Result<Vec<u8>, Error> {
    let mut decompressor: Decompressor<&[u8]> = Decompressor::new(compressed_cert, 4096);
    let mut decompressed: Vec<u8> = Vec::new();
    decompressor.read_to_end(&mut decompressed).map_err(|e| Error::Io(format!("brotli decompression error: {e}")))?;
    Ok(decompressed)
}

#[cfg(test)]
mod test_brotli {
    use crate::compression::brotli::{brotli_compress_cert, brotli_decompress_cert};
    use crate::encryption::random::Random;

    #[test]
    fn test_brotli_compress() {
        let rng: Random = Random::new();

        let mut cert: Vec<u8> = vec![0u8; 1500];
        rng.ochkagen(&mut cert).unwrap();

        let compressed_cert: Vec<u8> = brotli_compress_cert(&cert).unwrap();
        let decompressed_cert: Vec<u8> = brotli_decompress_cert(&compressed_cert).unwrap();

        assert_eq!(cert, decompressed_cert);
    }
}
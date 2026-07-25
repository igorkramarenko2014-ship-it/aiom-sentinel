#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Streaming cryptographic hashes and Shannon entropy.

use digest::Digest;
use md5::Md5;
use sentinel_core::{EntropyResult, HashSet, ScannerError};
use sha1::Sha1;
use sha2::Sha256;
use std::path::Path;
use tokio::{fs::File, io::AsyncReadExt};

const BUFFER_SIZE: usize = 64 * 1024;

pub async fn analyze(
    path: &Path,
    max_bytes: u64,
) -> Result<(HashSet, EntropyResult), ScannerError> {
    let mut file = File::open(path)
        .await
        .map_err(|error| io_error(path, error))?;
    let mut sha256 = Sha256::new();
    let mut sha1 = Sha1::new();
    let mut md5 = Md5::new();
    let mut counts = [0_u64; 256];
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    loop {
        let read = file
            .read(&mut buffer)
            .await
            .map_err(|error| io_error(path, error))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| ScannerError::LimitExceeded("file length overflow".to_owned()))?;
        if total > max_bytes {
            return Err(ScannerError::LimitExceeded(format!(
                "file exceeds {max_bytes} bytes"
            )));
        }
        let chunk = &buffer[..read];
        sha256.update(chunk);
        sha1.update(chunk);
        md5.update(chunk);
        for byte in chunk {
            counts[usize::from(*byte)] += 1;
        }
    }
    let entropy = entropy_from_counts(&counts, total);
    Ok((
        HashSet {
            sha256: hex::encode(sha256.finalize()),
            sha1: hex::encode(sha1.finalize()),
            md5: hex::encode(md5.finalize()),
        },
        EntropyResult {
            shannon_bits_per_byte: entropy,
        },
    ))
}

fn io_error(path: &Path, error: std::io::Error) -> ScannerError {
    ScannerError::Io {
        path: path.to_string_lossy().into_owned(),
        message: error.to_string(),
    }
}

#[must_use]
pub fn entropy(bytes: &[u8]) -> f64 {
    let mut counts = [0_u64; 256];
    for byte in bytes {
        counts[usize::from(*byte)] += 1;
    }
    entropy_from_counts(&counts, bytes.len() as u64)
}

fn entropy_from_counts(counts: &[u64; 256], total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let total = total as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f64 / total;
            -probability * probability.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn computes_known_digests() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"abc").unwrap();
        let (hashes, result) = analyze(file.path(), 3).await.unwrap();
        assert_eq!(
            hashes.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(hashes.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(hashes.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert!(result.shannon_bits_per_byte > 1.5);
    }
    #[test]
    fn entropy_is_zero_for_empty_or_uniform_data() {
        assert_eq!(entropy(&[]), 0.0);
        assert_eq!(entropy(&[7; 32]), 0.0);
    }
}

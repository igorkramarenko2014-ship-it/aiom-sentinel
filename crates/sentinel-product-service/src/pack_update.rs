use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone)]
pub struct PackCandidate {
    pub source: PathBuf,
    pub content_id: String,
}

pub fn validate_bundle(source: &Path, expected_sha256: &str) -> std::io::Result<PackCandidate> {
    let bytes = fs::read(source)?;
    let digest = hex::encode(Sha256::digest(&bytes));
    if digest != expected_sha256 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "pack hash mismatch",
        ));
    }
    Ok(PackCandidate {
        source: source.to_owned(),
        content_id: digest,
    })
}

pub fn stage(candidate: &PackCandidate, staging_root: &Path) -> std::io::Result<PathBuf> {
    fs::create_dir_all(staging_root)?;
    let target = staging_root.join(&candidate.content_id);
    if !target.exists() {
        fs::copy(&candidate.source, &target)?;
    }
    Ok(target)
}

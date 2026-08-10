use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineRecord {
    pub id: String,
    pub original_path: PathBuf,
    pub quarantine_path: PathBuf,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct QuarantineStoreV2 {
    pub root: PathBuf,
}

impl QuarantineStoreV2 {
    pub fn open(root: PathBuf) -> std::io::Result<Self> {
        fs::create_dir_all(root.join("journal"))?;
        fs::create_dir_all(root.join("staging"))?;
        fs::create_dir_all(root.join("objects"))?;
        fs::create_dir_all(root.join("metadata"))?;
        fs::create_dir_all(root.join("recovery"))?;
        fs::create_dir_all(root.join("restores"))?;
        fs::write(root.join("version"), b"sentinel-quarantine/v2\n")?;
        Ok(Self { root })
    }
    pub fn object_path(&self, id: &str) -> PathBuf {
        self.root.join("objects").join(id)
    }
    pub fn journal_path(&self, id: &str) -> PathBuf {
        self.root.join("journal").join(format!("{id}.json"))
    }
}

pub fn default_root() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("Library/Application Support/AIOM Sentinel/quarantine/v1")
}

pub fn load_records(root: &Path) -> Vec<QuarantineRecord> {
    fs::read(root.join("index.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

pub fn persist_records(root: &Path, records: &[QuarantineRecord]) -> std::io::Result<()> {
    fs::create_dir_all(root)?;
    let bytes =
        serde_json::to_vec_pretty(records).map_err(|e| std::io::Error::other(e.to_string()))?;
    fs::write(root.join("index.json"), bytes)
}

pub fn quarantine_file(source: &Path, root: &Path, id: &str) -> std::io::Result<QuarantineRecord> {
    let meta = fs::symlink_metadata(source)?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "only regular files can be quarantined",
        ));
    }
    fs::create_dir_all(root)?;
    let bytes = fs::read(source)?;
    let digest = hex::encode(Sha256::digest(&bytes));
    let destination = root.join(format!("{id}-{digest}"));
    if destination.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "quarantine destination exists",
        ));
    }
    fs::rename(source, &destination)?;
    Ok(QuarantineRecord {
        id: id.to_owned(),
        original_path: source.to_owned(),
        quarantine_path: destination,
        sha256: digest,
        size_bytes: meta.len(),
    })
}

pub fn restore_file(record: &QuarantineRecord) -> std::io::Result<()> {
    if record.original_path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "restore destination exists",
        ));
    }
    let bytes = fs::read(&record.quarantine_path)?;
    if hex::encode(Sha256::digest(&bytes)) != record.sha256 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "quarantine digest mismatch",
        ));
    }
    fs::rename(&record.quarantine_path, &record.original_path)
}

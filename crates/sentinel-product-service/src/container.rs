use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read,
    path::{Component, Path, PathBuf},
};
use zip::ZipArchive;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ContainerState {
    Complete,
    Partial,
    Encrypted,
    LimitExceeded,
    Failed,
    Unsupported,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContainerLimits {
    pub max_entries: usize,
    pub max_single_entry_bytes: u64,
    pub max_total_expanded_bytes: u64,
}

impl Default for ContainerLimits {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            max_single_entry_bytes: 512 * 1024 * 1024,
            max_total_expanded_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ContainerEntry {
    pub relative_path: String,
    pub declared_size: u64,
    pub subject_sha256: Option<String>,
    pub scanned: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContainerInspection {
    pub state: ContainerState,
    pub container_type: String,
    pub entries: Vec<ContainerEntry>,
    pub expanded_bytes: u64,
    pub errors: Vec<String>,
}

fn safe_relative(path: &Path) -> bool {
    !path.is_absolute() && path.components().all(|c| matches!(c, Component::Normal(_)))
}

pub fn inspect_zip(path: &Path, limits: &ContainerLimits) -> std::io::Result<ContainerInspection> {
    let file = File::open(path)?;
    let mut archive = ZipArchive::new(file)?;
    let mut result = ContainerInspection {
        state: ContainerState::Complete,
        container_type: "ZIP".into(),
        entries: Vec::new(),
        expanded_bytes: 0,
        errors: Vec::new(),
    };
    for index in 0..archive.len() {
        if index >= limits.max_entries {
            result.state = ContainerState::LimitExceeded;
            result.errors.push("max_entries exceeded".into());
            break;
        }
        let mut entry = archive.by_index(index)?;
        let name = PathBuf::from(entry.name());
        if !safe_relative(&name) {
            result.state = ContainerState::Partial;
            result
                .errors
                .push(format!("rejected path: {}", entry.name()));
            continue;
        }
        let size = entry.size();
        if size > limits.max_single_entry_bytes
            || result.expanded_bytes.saturating_add(size) > limits.max_total_expanded_bytes
        {
            result.state = ContainerState::LimitExceeded;
            result
                .errors
                .push(format!("size limit exceeded: {}", entry.name()));
            break;
        }
        let mut digest = Sha256::new();
        let mut bytes = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        while let Some(read) = entry.read(&mut buffer).ok().filter(|n| *n > 0) {
            digest.update(&buffer[..read]);
            bytes += read as u64;
        }
        result.expanded_bytes += bytes;
        result.entries.push(ContainerEntry {
            relative_path: entry.name().to_owned(),
            declared_size: size,
            subject_sha256: Some(hex::encode(digest.finalize())),
            scanned: true,
            error: None,
        });
    }
    Ok(result)
}

pub fn inspect_tar(path: &Path, limits: &ContainerLimits) -> std::io::Result<ContainerInspection> {
    let file = File::open(path)?;
    let mut archive = tar::Archive::new(file);
    let mut result = ContainerInspection {
        state: ContainerState::Complete,
        container_type: "TAR".into(),
        entries: Vec::new(),
        expanded_bytes: 0,
        errors: Vec::new(),
    };
    for (index, item) in archive.entries()?.enumerate() {
        if index >= limits.max_entries {
            result.state = ContainerState::LimitExceeded;
            result.errors.push("max_entries exceeded".into());
            break;
        }
        let mut entry = item?;
        let path = entry.path()?.into_owned();
        if !safe_relative(&path) {
            result.state = ContainerState::Partial;
            result
                .errors
                .push(format!("rejected path: {}", path.display()));
            continue;
        }
        let entry_type = entry.header().entry_type();
        if !entry_type.is_file() {
            result.state = ContainerState::Partial;
            result
                .errors
                .push(format!("non-regular entry: {}", path.display()));
            continue;
        }
        let declared = entry.header().size()?;
        if declared > limits.max_single_entry_bytes
            || result.expanded_bytes.saturating_add(declared) > limits.max_total_expanded_bytes
        {
            result.state = ContainerState::LimitExceeded;
            result
                .errors
                .push(format!("size limit exceeded: {}", path.display()));
            break;
        }
        let mut digest = Sha256::new();
        let copied = std::io::copy(&mut entry, &mut HashWriter(&mut digest))?;
        result.expanded_bytes += copied;
        result.entries.push(ContainerEntry {
            relative_path: path.to_string_lossy().into_owned(),
            declared_size: declared,
            subject_sha256: Some(hex::encode(digest.finalize())),
            scanned: true,
            error: None,
        });
    }
    Ok(result)
}

struct HashWriter<'a>(&'a mut Sha256);
impl std::io::Write for HashWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    #[test]
    fn rejects_traversal_and_hashes_regular_entries() {
        let mut file = NamedTempFile::new().expect("temp");
        {
            let mut writer = zip::ZipWriter::new(&mut file);
            let options = zip::write::SimpleFileOptions::default();
            writer.start_file("ok.txt", options).expect("entry");
            writer.write_all(b"hello").expect("bytes");
            writer.start_file("../escape", options).expect("entry");
            writer.write_all(b"bad").expect("bytes");
            writer.finish().expect("zip");
        }
        let result = inspect_zip(file.path(), &ContainerLimits::default()).expect("inspect");
        assert_eq!(result.entries.len(), 1);
        assert!(!result.errors.is_empty());
        assert_eq!(
            result.entries[0].subject_sha256.as_deref(),
            Some("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        );
    }
}

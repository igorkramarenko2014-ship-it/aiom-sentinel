#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Bounded metadata-only Portable Executable parser.

use sentinel_core::{PeMetadata, PeSection};
use sentinel_hash::entropy;
use thiserror::Error;

const MAX_PE_BYTES: usize = 256 * 1024 * 1024;
const MAX_SECTIONS: usize = 96;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PeError {
    #[error("input is not a Portable Executable")]
    NotPe,
    #[error("truncated PE structure: {0}")]
    Truncated(&'static str),
    #[error("PE parser input exceeds the configured limit")]
    InputTooLarge,
    #[error("PE declares too many sections")]
    TooManySections,
}

pub fn parse(bytes: &[u8]) -> Result<PeMetadata, PeError> {
    if bytes.len() > MAX_PE_BYTES {
        return Err(PeError::InputTooLarge);
    }
    if bytes.get(..2) != Some(b"MZ") {
        return Err(PeError::NotPe);
    }
    let pe_offset = read_u32(bytes, 0x3c, "DOS header")? as usize;
    if bytes.get(pe_offset..pe_offset.saturating_add(4)) != Some(b"PE\0\0") {
        return Err(PeError::NotPe);
    }
    let coff = pe_offset
        .checked_add(4)
        .ok_or(PeError::Truncated("COFF offset"))?;
    let machine = read_u16(bytes, coff, "COFF machine")?;
    let section_count = usize::from(read_u16(bytes, coff + 2, "COFF section count")?);
    if section_count > MAX_SECTIONS {
        return Err(PeError::TooManySections);
    }
    let timestamp = read_u32(bytes, coff + 4, "COFF timestamp")?;
    let optional_size = usize::from(read_u16(bytes, coff + 16, "optional header size")?);
    let optional = coff + 20;
    let magic = read_u16(bytes, optional, "optional header magic")?;
    let data_directory = match magic {
        0x10b => optional + 96,
        0x20b => optional + 112,
        _ => return Err(PeError::NotPe),
    };
    let certificate_table_present =
        read_u32(bytes, data_directory + (8 * 4), "certificate table RVA").unwrap_or(0) != 0;
    let section_table = optional
        .checked_add(optional_size)
        .ok_or(PeError::Truncated("section table"))?;
    let mut sections = Vec::with_capacity(section_count);
    let mut warnings = Vec::new();
    for index in 0..section_count {
        let offset = section_table
            .checked_add(index * 40)
            .ok_or(PeError::Truncated("section header"))?;
        let header = bytes
            .get(offset..offset + 40)
            .ok_or(PeError::Truncated("section header"))?;
        let name_end = header[..8].iter().position(|byte| *byte == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&header[..name_end]).into_owned();
        let virtual_size = u32::from_le_bytes(
            header[8..12]
                .try_into()
                .map_err(|_| PeError::Truncated("virtual size"))?,
        );
        let raw_size = u32::from_le_bytes(
            header[16..20]
                .try_into()
                .map_err(|_| PeError::Truncated("raw size"))?,
        );
        let raw_offset = u32::from_le_bytes(
            header[20..24]
                .try_into()
                .map_err(|_| PeError::Truncated("raw offset"))?,
        ) as usize;
        let raw_end = raw_offset
            .saturating_add(raw_size as usize)
            .min(bytes.len());
        let section_entropy = bytes.get(raw_offset..raw_end).map_or(0.0, entropy);
        if raw_offset.saturating_add(raw_size as usize) > bytes.len() {
            warnings.push(format!("section {name} raw data is truncated"));
        }
        sections.push(PeSection {
            name,
            raw_size,
            virtual_size,
            entropy: section_entropy,
        });
    }
    Ok(PeMetadata {
        machine,
        timestamp,
        sections,
        certificate_table_present,
        warnings,
    })
}

fn read_u16(bytes: &[u8], offset: usize, label: &'static str) -> Result<u16, PeError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(PeError::Truncated(label))?;
    Ok(u16::from_le_bytes(
        value.try_into().map_err(|_| PeError::Truncated(label))?,
    ))
}
fn read_u32(bytes: &[u8], offset: usize, label: &'static str) -> Result<u32, PeError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(PeError::Truncated(label))?;
    Ok(u32::from_le_bytes(
        value.try_into().map_err(|_| PeError::Truncated(label))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_non_pe_data() {
        assert_eq!(parse(b"harmless text"), Err(PeError::NotPe));
    }
    #[test]
    fn malformed_mz_does_not_panic() {
        assert!(matches!(parse(b"MZ"), Err(PeError::Truncated(_))));
    }
}

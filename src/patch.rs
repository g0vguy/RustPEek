use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Serialize, Deserialize)]
pub struct RustPatch {
    pub version: u32,
    pub target_filename: String,
    pub target_size: u64,
    pub target_sha256: String,
    pub patches: Vec<PatchEntry>,
}

#[derive(Serialize, Deserialize)]
pub struct PatchEntry {
    pub file_offset: u64,
    pub original_bytes: Vec<u8>,
    pub patched_bytes: Vec<u8>,
    pub description: Option<String>,
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn export_patch(
    orig_path: &str,
    orig_data: &[u8],
    entries: &[&crate::differ::DiffEntry],
) -> RustPatch {
    let target_filename = Path::new(orig_path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| orig_path.to_string());

    let patches = entries
        .iter()
        .map(|e| {
            let start = e.context_before;
            let end = e.original_bytes.len() - e.context_after;
            PatchEntry {
                file_offset: e.file_offset,
                original_bytes: e.original_bytes[start..end].to_vec(),
                patched_bytes: e.modified_bytes[start..end].to_vec(),
                description: e.pattern_label.clone(),
            }
        })
        .collect();

    RustPatch {
        version: 1,
        target_filename,
        target_size: orig_data.len() as u64,
        target_sha256: sha256_hex(orig_data),
        patches,
    }
}

pub fn apply_patch(patch_path: &Path, target_path: &Path, output_path: &Path, force: bool) -> Result<usize> {
    let patch_bytes = std::fs::read(patch_path)
        .with_context(|| format!("cannot read patch '{}'", patch_path.display()))?;
    let patch: RustPatch = serde_json::from_slice(&patch_bytes)
        .with_context(|| "patch file is not valid JSON / RustPatch format")?;

    if patch.version != 1 {
        bail!("unsupported patch version {}", patch.version);
    }

    let mut target = std::fs::read(target_path)
        .with_context(|| format!("cannot read target '{}'", target_path.display()))?;

    if !force {
        let actual = sha256_hex(&target);
        if actual != patch.target_sha256 {
            bail!(
                "SHA-256 mismatch: expected {} got {}\nUse --force to skip verification.",
                patch.target_sha256,
                actual
            );
        }
    }

    for (i, entry) in patch.patches.iter().enumerate() {
        let start = entry.file_offset as usize;
        let end = start + entry.original_bytes.len();

        if end > target.len() {
            bail!(
                "patch entry {} at offset {:#x} extends beyond file size {}",
                i,
                entry.file_offset,
                target.len()
            );
        }

        if target[start..end] != entry.original_bytes[..] {
            bail!(
                "patch entry {} at offset {:#x}: original bytes mismatch\n  expected: {}\n  found:    {}",
                i,
                entry.file_offset,
                hex::encode(&entry.original_bytes),
                hex::encode(&target[start..end])
            );
        }

        target[start..end].copy_from_slice(&entry.patched_bytes);
    }

    std::fs::write(output_path, &target)
        .with_context(|| format!("cannot write output '{}'", output_path.display()))?;

    Ok(patch.patches.len())
}

pub fn to_ips(entries: &[&crate::differ::DiffEntry]) -> Vec<u8> {
    let mut out = b"PATCH".to_vec();
    for e in entries {
        let start = e.context_before;
        let end = e.original_bytes.len() - e.context_after;
        let patched = &e.modified_bytes[start..end];
        let offset = e.file_offset as usize;
        let total = patched.len();

        let mut written = 0;
        while written < total {
            let chunk_end = (written + 0xFFFF).min(total);
            let chunk = &patched[written..chunk_end];
            let chunk_offset = offset + written;

            if chunk_offset > 0xFFFFFF {
                // RUP extension: write EOE (0x454F45) marker, 4-byte offset, 2-byte size, data
                out.extend_from_slice(b"EOE");
                out.push(((chunk_offset >> 24) & 0xFF) as u8);
                out.push(((chunk_offset >> 16) & 0xFF) as u8);
                out.push(((chunk_offset >> 8) & 0xFF) as u8);
                out.push((chunk_offset & 0xFF) as u8);
            } else {
                // Standard IPS: 3-byte big-endian offset
                out.push(((chunk_offset >> 16) & 0xFF) as u8);
                out.push(((chunk_offset >> 8) & 0xFF) as u8);
                out.push((chunk_offset & 0xFF) as u8);
            }

            let size = chunk.len();
            out.push(((size >> 8) & 0xFF) as u8);
            out.push((size & 0xFF) as u8);
            out.extend_from_slice(chunk);

            written += chunk.len();
        }
    }
    out.extend_from_slice(b"EOF");
    out
}

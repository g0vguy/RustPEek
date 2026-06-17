use crate::address::{file_offset_to_rva, rva_to_va, section_for_rva};
use crate::pe_parser::PeInfo;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct DiffEntry {
    pub rva: u64,
    pub va: u64,
    pub file_offset: u64,
    pub original_bytes: Vec<u8>,
    pub modified_bytes: Vec<u8>,
    pub context_before: usize,
    pub context_after: usize,
    pub section_index: usize,
    pub section_name: String,
    pub pattern_label: Option<String>,
    pub entropy_original: f64,
    pub entropy_modified: f64,
    pub entropy_delta: f64,
}

pub fn compare(orig: &PeInfo, modif: &PeInfo, context: usize, headers_only: bool) -> Vec<DiffEntry> {
    let len = orig.raw_data.len().min(modif.raw_data.len());

    let scan_len = if headers_only {
        let header_end = orig.sections.iter().map(|s| s.raw_offset).min().unwrap_or(len as u64);
        header_end.min(len as u64) as usize
    } else {
        len
    };

    let diff_offsets: Vec<u64> = (0..scan_len)
        .filter(|&i| orig.raw_data[i] != modif.raw_data[i])
        .map(|i| i as u64)
        .collect();

    group_runs(&diff_offsets)
        .into_iter()
        .filter_map(|(start, end)| {
            let ctx_start = start.saturating_sub(context as u64);
            let ctx_end = (end + context as u64).min(scan_len as u64 - 1);

            // The exact diff slice (not the full context)
            let diff_orig = &orig.raw_data[start as usize..=end as usize];
            let diff_mod  = &modif.raw_data[start as usize..=end as usize];

            let pattern = detect_pattern(diff_orig, diff_mod);
            let entropy_orig = compute_entropy(diff_orig);
            let entropy_mod  = compute_entropy(diff_mod);
            let entropy_delta = (entropy_mod - entropy_orig).abs();

            let rva = file_offset_to_rva(start, &orig.sections)?;
            let va = rva_to_va(rva, orig.image_base);
            let (section_index, section_name) = section_for_rva(rva, &orig.sections);

            Some(DiffEntry {
                rva,
                va,
                file_offset: start,
                original_bytes: orig.raw_data[ctx_start as usize..=ctx_end as usize].to_vec(),
                modified_bytes: modif.raw_data[ctx_start as usize..=ctx_end as usize].to_vec(),
                context_before: (start - ctx_start) as usize,
                context_after: (ctx_end - end) as usize,
                section_index,
                section_name,
                pattern_label: pattern,
                entropy_original: entropy_orig,
                entropy_modified: entropy_mod,
                entropy_delta,
            })
        })
        .collect()
}

fn group_runs(offsets: &[u64]) -> Vec<(u64, u64)> {
    if offsets.is_empty() {
        return Vec::new();
    }
    let mut runs = Vec::new();
    let mut start = offsets[0];
    let mut end = offsets[0];
    for &off in &offsets[1..] {
        if off == end + 1 {
            end = off;
        } else {
            runs.push((start, end));
            start = off;
            end = off;
        }
    }
    runs.push((start, end));
    runs
}

fn detect_pattern(_orig: &[u8], modified: &[u8]) -> Option<String> {
    if modified.is_empty() {
        return None;
    }

    if modified.iter().all(|&b| b == 0x90) {
        return Some("NOP sled".to_string());
    }

    if modified.len() >= 2 && modified[0] == 0xEB {
        return Some("JMP short".to_string());
    }

    if modified.len() >= 5 && modified[0] == 0xE9 {
        return Some("JMP near".to_string());
    }

    if modified.last() == Some(&0xC3) {
        return Some("RET".to_string());
    }

    if modified.len() >= 3 && modified[modified.len() - 3] == 0xC2 {
        return Some("RET imm".to_string());
    }

    if modified.last() == Some(&0xCB) {
        return Some("RET far".to_string());
    }

    if modified.len() >= 3 && modified[modified.len() - 3] == 0xCA {
        return Some("RET far imm".to_string());
    }
    None
}

fn compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let len = data.len() as f64;
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}
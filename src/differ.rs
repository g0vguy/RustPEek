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
    pub section_index: usize,
    pub section_name: String,
}

pub fn compare(orig: &PeInfo, modif: &PeInfo) -> Vec<DiffEntry> {
    let len = orig.raw_data.len().min(modif.raw_data.len());

    let diff_offsets: Vec<u64> = (0..len)
        .filter(|&i| orig.raw_data[i] != modif.raw_data[i])
        .map(|i| i as u64)
        .collect();

    group_runs(&diff_offsets)
        .into_iter()
        .filter_map(|(start, end)| {
            let rva = file_offset_to_rva(start, &orig.sections)?;
            let va = rva_to_va(rva, orig.image_base);
            let (section_index, section_name) = section_for_rva(rva, &orig.sections);
            Some(DiffEntry {
                rva,
                va,
                file_offset: start,
                original_bytes: orig.raw_data[start as usize..=end as usize].to_vec(),
                modified_bytes: modif.raw_data[start as usize..=end as usize].to_vec(),
                section_index,
                section_name,
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

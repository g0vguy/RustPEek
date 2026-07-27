use crate::pe_parser::SectionInfo;

pub fn file_offset_to_rva(offset: u64, sections: &[SectionInfo]) -> Option<u64> {
    for s in sections {
        if s.raw_size > 0 && offset >= s.raw_offset && offset < s.raw_offset + s.raw_size {
            return Some(s.virtual_address + (offset - s.raw_offset));
        }
    }

    if offset < sections.iter().map(|s| s.raw_offset).min().unwrap_or(u64::MAX) {
        return Some(offset);
    }
    None
}

pub fn rva_to_va(rva: u64, image_base: u64) -> u64 {
    image_base + rva
}

pub fn section_for_rva(rva: u64, sections: &[SectionInfo]) -> (usize, String) {
    sections
        .iter()
        .find(|s| {
            let size = if s.virtual_size > 0 { s.virtual_size } else { s.raw_size };
            rva >= s.virtual_address && rva < s.virtual_address + size
        })
        .map(|s| (s.index, s.name.clone()))
        .unwrap_or((0, "unknown".to_string()))
}

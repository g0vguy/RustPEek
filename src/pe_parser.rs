use anyhow::{bail, Context, Result};
use goblin::pe::PE;

#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub index: usize,
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_offset: u64,
    pub raw_size: u64,
}

#[derive(Debug)]
pub struct PeInfo {
    pub image_base: u64,
    pub sections: Vec<SectionInfo>,
    pub raw_data: Vec<u8>,
}

pub fn load(path: &str) -> Result<PeInfo> {
    let raw_data = std::fs::read(path).with_context(|| format!("cannot read '{path}'"))?;
    let pe = PE::parse(&raw_data).with_context(|| format!("'{path}' is not a valid PE file"))?;

    let image_base = match &pe.header.optional_header {
        Some(oh) => oh.windows_fields.image_base,
        None => bail!("'{path}' has no Optional Header"),
    };

    let sections = pe
        .sections
        .iter()
        .enumerate()
        .map(|(i, s)| SectionInfo {
            index: i + 1,
            name: s.name().unwrap_or("?").trim_end_matches('\0').to_string(),
            virtual_address: s.virtual_address as u64,
            virtual_size: s.virtual_size as u64,
            raw_offset: s.pointer_to_raw_data as u64,
            raw_size: s.size_of_raw_data as u64,
        })
        .collect();

    Ok(PeInfo { image_base, sections, raw_data })
}

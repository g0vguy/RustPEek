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

#[derive(Debug, Clone)]
pub struct ImportEntry {
    pub dll: String,
    pub name: Option<String>,
    pub ordinal: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct ExportEntry {
    pub name: Option<String>,
    pub ordinal: u16,
    pub rva: u32,
    pub forward_name: Option<String>,
}

#[derive(Debug)]
pub struct PeInfo {
    pub image_base: u64,
    pub is_64bit: bool,
    pub sections: Vec<SectionInfo>,
    pub raw_data: Vec<u8>,
    pub pdb_path: Option<String>,
    pub imports: Vec<ImportEntry>,
    pub exports: Vec<ExportEntry>,
}

pub fn load(path: &str) -> Result<PeInfo> {
    let raw_data = std::fs::read(path).with_context(|| format!("cannot read '{path}'"))?;
    let pe = PE::parse(&raw_data).with_context(|| format!("'{path}' is not a valid PE file"))?;

    let oh = match &pe.header.optional_header {
        Some(oh) => oh,
        None => bail!("'{path}' has no Optional Header"),
    };

    let image_base = oh.windows_fields.image_base;
    let is_64bit = pe.is_64;

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

    let imports = pe
        .imports
        .iter()
        .map(|imp| ImportEntry {
            dll: imp.dll.to_ascii_lowercase(),
            name: if imp.name.is_empty() { None } else { Some(imp.name.to_string()) },
            ordinal: if imp.name.is_empty() { Some(imp.ordinal as u16) } else { None },
        })
        .collect();

    let exports = pe
        .exports
        .iter()
        .enumerate()
        .map(|(i, exp)| ExportEntry {
            name: exp.name.map(|n| n.to_string()),
            ordinal: i as u16,
            rva: exp.rva as u32,
            forward_name: exp.reexport.as_ref().and_then(|r| match r {
                goblin::pe::export::Reexport::DLLName { export, lib } => {
                    Some(format!("{}.{}", lib, export))
                }
                goblin::pe::export::Reexport::DLLOrdinal { ordinal, lib } => {
                    Some(format!("{}.#{}", lib, ordinal))
                }
            }),
        })
        .collect();

    let pdb_path = extract_pdb_path(&pe);

    Ok(PeInfo { image_base, is_64bit, sections, raw_data, pdb_path, imports, exports })
}

fn extract_pdb_path(pe: &PE) -> Option<String> {
    pe.debug_data
        .as_ref()?
        .codeview_pdb70_debug_info
        .map(|cv| {
            String::from_utf8_lossy(cv.filename)
                .trim_end_matches('\0')
                .to_string()
        })
}

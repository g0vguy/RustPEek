use crate::pe_parser::{ExportEntry, ImportEntry, PeInfo};
use serde::Serialize;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum SemanticChange {
    ImportAdded { dll: String, name: Option<String>, ordinal: Option<u16> },
    ImportRemoved { dll: String, name: Option<String>, ordinal: Option<u16> },
    ExportAdded { name: Option<String>, ordinal: u16, rva: u32 },
    ExportRemoved { name: Option<String>, ordinal: u16, rva: u32 },
    ExportForwarded { ordinal: u16, target: String },
    ResourceTypeAdded { rtype: String, count: usize },
    ResourceTypeRemoved { rtype: String, count: usize },
    ResourceModified { rtype: String, name: String, size_delta: i64 },
    ManifestChanged,
    VersionInfoChanged,
}

impl SemanticChange {
    pub fn category(&self) -> &'static str {
        match self {
            Self::ImportAdded { .. } | Self::ImportRemoved { .. } => "Import",
            Self::ExportAdded { .. }
            | Self::ExportRemoved { .. }
            | Self::ExportForwarded { .. } => "Export",
            _ => "Resource",
        }
    }

    pub fn change_type(&self) -> &'static str {
        match self {
            Self::ImportAdded { .. } => "Added",
            Self::ImportRemoved { .. } => "Removed",
            Self::ExportAdded { .. } => "Added",
            Self::ExportRemoved { .. } => "Removed",
            Self::ExportForwarded { .. } => "Forwarded",
            Self::ResourceTypeAdded { .. } => "Added",
            Self::ResourceTypeRemoved { .. } => "Removed",
            Self::ResourceModified { .. } => "Modified",
            Self::ManifestChanged => "Modified",
            Self::VersionInfoChanged => "Modified",
        }
    }

    pub fn detail(&self) -> String {
        match self {
            Self::ImportAdded { dll, name, ordinal } | Self::ImportRemoved { dll, name, ordinal } => {
                match name {
                    Some(n) => format!("{}!{}", dll, n),
                    None => format!("{}!#{}", dll, ordinal.unwrap_or(0)),
                }
            }
            Self::ExportAdded { name, ordinal, rva } | Self::ExportRemoved { name, ordinal, rva } => {
                match name {
                    Some(n) => format!("{} (ord={}, rva={:#x})", n, ordinal, rva),
                    None => format!("ord={} rva={:#x}", ordinal, rva),
                }
            }
            Self::ExportForwarded { ordinal, target } => format!("ord={} -> {}", ordinal, target),
            Self::ResourceTypeAdded { rtype, count } => format!("{} (+{})", rtype, count),
            Self::ResourceTypeRemoved { rtype, count } => format!("{} (-{})", rtype, count),
            Self::ResourceModified { rtype, name, size_delta } => {
                format!("{}/{} ({:+} bytes)", rtype, name, size_delta)
            }
            Self::ManifestChanged => "RT_MANIFEST changed".to_string(),
            Self::VersionInfoChanged => "RT_VERSION changed".to_string(),
        }
    }
}

#[derive(Debug, Default, Serialize)]
pub struct SemanticDiff {
    pub imports: Vec<SemanticChange>,
    pub exports: Vec<SemanticChange>,
    pub resources: Vec<SemanticChange>,
}

impl SemanticDiff {
    pub fn all(&self) -> Vec<&SemanticChange> {
        self.imports
            .iter()
            .chain(self.exports.iter())
            .chain(self.resources.iter())
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.imports.is_empty() && self.exports.is_empty() && self.resources.is_empty()
    }
}

pub fn analyze_semantic(orig: &PeInfo, modif: &PeInfo) -> SemanticDiff {
    let mut diff = SemanticDiff::default();
    diff.imports = diff_imports(&orig.imports, &modif.imports);
    diff.exports = diff_exports(&orig.exports, &modif.exports);
    diff.resources = diff_resources(&orig.raw_data, &modif.raw_data);
    diff
}

fn import_key(e: &ImportEntry) -> String {
    match &e.name {
        Some(n) => format!("{}!{}", e.dll, n),
        None => format!("{}!#{}", e.dll, e.ordinal.unwrap_or(0)),
    }
}

fn diff_imports(orig: &[ImportEntry], modif: &[ImportEntry]) -> Vec<SemanticChange> {
    let orig_set: HashSet<String> = orig.iter().map(import_key).collect();
    let mod_set: HashSet<String> = modif.iter().map(import_key).collect();

    let orig_map: HashMap<String, &ImportEntry> = orig.iter().map(|e| (import_key(e), e)).collect();
    let mod_map: HashMap<String, &ImportEntry> = modif.iter().map(|e| (import_key(e), e)).collect();

    let mut changes = Vec::new();
    for key in mod_set.difference(&orig_set) {
        let e = mod_map[key];
        changes.push(SemanticChange::ImportAdded {
            dll: e.dll.clone(),
            name: e.name.clone(),
            ordinal: e.ordinal,
        });
    }
    for key in orig_set.difference(&mod_set) {
        let e = orig_map[key];
        changes.push(SemanticChange::ImportRemoved {
            dll: e.dll.clone(),
            name: e.name.clone(),
            ordinal: e.ordinal,
        });
    }
    changes.sort_by(|a, b| a.detail().cmp(&b.detail()));
    changes
}

fn diff_exports(orig: &[ExportEntry], modif: &[ExportEntry]) -> Vec<SemanticChange> {
    let orig_map: HashMap<u16, &ExportEntry> = orig.iter().map(|e| (e.ordinal, e)).collect();
    let mod_map: HashMap<u16, &ExportEntry> = modif.iter().map(|e| (e.ordinal, e)).collect();

    let orig_ords: HashSet<u16> = orig_map.keys().copied().collect();
    let mod_ords: HashSet<u16> = mod_map.keys().copied().collect();

    let mut changes = Vec::new();
    for &ord in mod_ords.difference(&orig_ords) {
        let e = mod_map[&ord];
        changes.push(SemanticChange::ExportAdded { name: e.name.clone(), ordinal: ord, rva: e.rva });
    }
    for &ord in orig_ords.difference(&mod_ords) {
        let e = orig_map[&ord];
        changes.push(SemanticChange::ExportRemoved { name: e.name.clone(), ordinal: ord, rva: e.rva });
    }
    // Detect newly forwarded exports
    for (&ord, e) in &mod_map {
        if let Some(ref fwd) = e.forward_name {
            let was_forwarded = orig_map.get(&ord).and_then(|o| o.forward_name.as_ref()).is_some();
            if !was_forwarded {
                changes.push(SemanticChange::ExportForwarded { ordinal: ord, target: fwd.clone() });
            }
        }
    }
    changes
}

fn rtype_name(id: u32) -> String {
    match id {
        1 => "RT_CURSOR".to_string(),
        2 => "RT_BITMAP".to_string(),
        3 => "RT_ICON".to_string(),
        4 => "RT_MENU".to_string(),
        5 => "RT_DIALOG".to_string(),
        6 => "RT_STRING".to_string(),
        9 => "RT_ACCELERATOR".to_string(),
        14 => "RT_GROUP_ICON".to_string(),
        16 => "RT_VERSION".to_string(),
        24 => "RT_MANIFEST".to_string(),
        n => format!("RT_{}", n),
    }
}

fn diff_resources(orig_data: &[u8], mod_data: &[u8]) -> Vec<SemanticChange> {
    let orig_res = parse_resources(orig_data);
    let mod_res = parse_resources(mod_data);

    let mut changes = Vec::new();

    // (type_id, name_id) -> size
    let orig_map: HashMap<(u32, u32), u32> = orig_res;
    let mod_map: HashMap<(u32, u32), u32> = mod_res;

    // Count by type
    let mut orig_type_counts: HashMap<u32, usize> = HashMap::new();
    let mut mod_type_counts: HashMap<u32, usize> = HashMap::new();
    for (t, _) in orig_map.keys() { *orig_type_counts.entry(*t).or_default() += 1; }
    for (t, _) in mod_map.keys() { *mod_type_counts.entry(*t).or_default() += 1; }

    let all_types: HashSet<u32> = orig_type_counts.keys().chain(mod_type_counts.keys()).copied().collect();
    for t in &all_types {
        let oc = orig_type_counts.get(t).copied().unwrap_or(0);
        let mc = mod_type_counts.get(t).copied().unwrap_or(0);
        if mc > oc {
            changes.push(SemanticChange::ResourceTypeAdded { rtype: rtype_name(*t), count: mc - oc });
        } else if oc > mc {
            changes.push(SemanticChange::ResourceTypeRemoved { rtype: rtype_name(*t), count: oc - mc });
        }
    }

    // Per-entry size changes
    let all_keys: HashSet<(u32, u32)> = orig_map.keys().chain(mod_map.keys()).copied().collect();
    for key in &all_keys {
        if let (Some(&os), Some(&ms)) = (orig_map.get(key), mod_map.get(key)) {
            if os != ms {
                let delta = ms as i64 - os as i64;
                let rtype = rtype_name(key.0);
                match key.0 {
                    24 => changes.push(SemanticChange::ManifestChanged),
                    16 => changes.push(SemanticChange::VersionInfoChanged),
                    _ => changes.push(SemanticChange::ResourceModified {
                        rtype,
                        name: format!("#{}", key.1),
                        size_delta: delta,
                    }),
                }
            }
        }
    }

    changes
}

/// Returns a map of (type_id, name_id) -> data_size using pelite.
fn parse_resources(data: &[u8]) -> HashMap<(u32, u32), u32> {
    use pelite::pe64::{Pe as _, PeFile};
    use pelite::pe32::{Pe as _, PeFile as PeFile32};

    let mut map = HashMap::new();

    if let Ok(pe) = PeFile::from_bytes(data) {
        if let Ok(resources) = pe.resources() {
            walk_resources(resources, &mut map);
        }
    } else if let Ok(pe) = PeFile32::from_bytes(data) {
        if let Ok(resources) = pe.resources() {
            walk_resources(resources, &mut map);
        }
    }

    map
}

fn walk_resources(
    resources: pelite::resources::Resources,
    map: &mut HashMap<(u32, u32), u32>,
) {
    let root = match resources.root() {
        Ok(r) => r,
        Err(_) => return,
    };

    for type_entry in root.entries() {
        let type_id = match type_entry.name() {
            Ok(pelite::resources::Name::Id(id)) => id,
            _ => continue,
        };
        let type_dir = match type_entry.entry() {
            Ok(e) => match e.dir() {
                Some(d) => d,
                None => continue,
            },
            Err(_) => continue,
        };
        for name_entry in type_dir.entries() {
            let name_id = match name_entry.name() {
                Ok(pelite::resources::Name::Id(id)) => id,
                _ => 0,
            };
            let name_dir = match name_entry.entry() {
                Ok(e) => match e.dir() {
                    Some(d) => d,
                    None => continue,
                },
                Err(_) => continue,
            };
            for lang_entry in name_dir.entries() {
                let data_entry = match lang_entry.entry() {
                    Ok(e) => match e.data() {
                        Some(d) => d,
                        None => continue,
                    },
                    Err(_) => continue,
                };
                if let Ok(bytes) = data_entry.bytes() {
                    map.insert((type_id, name_id), bytes.len() as u32);
                }
            }
        }
    }
}

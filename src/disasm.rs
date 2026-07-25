use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};

pub struct DisasmLine {
    pub address: u64,
    pub orig_mnemonic: String,
    pub mod_mnemonic: String,
    pub is_changed: bool,
}

pub fn disassemble_region(
    va: u64,
    original: &[u8],
    modified: &[u8],
    is_64bit: bool,
) -> Vec<DisasmLine> {
    let bitness = if is_64bit { 64 } else { 32 };
    let orig_insns = decode_stream(original, va, bitness);
    let mod_insns = decode_stream(modified, va, bitness);

    // Align by VA: build a map from address -> mnemonic for each stream
    let orig_map: std::collections::BTreeMap<u64, (String, usize)> = orig_insns
        .iter()
        .map(|(addr, text, len)| (*addr, (text.clone(), *len)))
        .collect();
    let mod_map: std::collections::BTreeMap<u64, (String, usize)> = mod_insns
        .iter()
        .map(|(addr, text, len)| (*addr, (text.clone(), *len)))
        .collect();

    // Union of all addresses, sorted
    let mut addrs: Vec<u64> = orig_map.keys().chain(mod_map.keys()).copied().collect();
    addrs.sort_unstable();
    addrs.dedup();

    addrs
        .into_iter()
        .map(|addr| {
            let orig_text = orig_map.get(&addr).map(|(t, _)| t.clone()).unwrap_or_default();
            let mod_text = mod_map.get(&addr).map(|(t, _)| t.clone()).unwrap_or_default();
            let is_changed = orig_text != mod_text;
            DisasmLine {
                address: addr,
                orig_mnemonic: orig_text,
                mod_mnemonic: mod_text,
                is_changed,
            }
        })
        .collect()
}

fn decode_stream(bytes: &[u8], ip: u64, bitness: u32) -> Vec<(u64, String, usize)> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let mut decoder = Decoder::with_ip(bitness, bytes, ip, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    let mut output = String::new();
    let mut result = Vec::new();
    let mut insn = Instruction::default();

    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        output.clear();
        formatter.format(&insn, &mut output);
        let len = insn.len();
        let addr = insn.ip();
        result.push((addr, output.clone(), len));
    }
    result
}

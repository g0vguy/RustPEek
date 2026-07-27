mod address;
mod differ;
mod disasm;
mod output;
mod patch;
mod pe_parser;
mod semantic;

use anyhow::{Context, Result};
use clap::Parser;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "RustPEek", version, about = "Compare two PE files and report byte-level differences")]
struct DiffCli {
    original: String,
    modified: String,

    #[arg(long, short)]
    output: Option<String>,

    #[arg(long, short, default_value = "table")]
    format: String,

    #[arg(long, short)]
    section: Option<String>,

    #[arg(long, short = 'b')]
    min_bytes: Option<usize>,

    #[arg(long, short = 'c', default_value = "0")]
    context: usize,

    #[arg(long, short = 'i', num_args = 1..)]
    ignore_section: Vec<String>,

    #[arg(long)]
    diff_only_headers: bool,
}

#[derive(Parser, Debug)]
#[command(name = "apply", about = "Apply an RPK patch to a target file")]
struct ApplyCli {
    patch: String,
    target: String,
    output: String,

    #[arg(long)]
    force: bool,
}

fn main() -> Result<()> {
    // Manually inspect argv so `apply` can be a subcommand while the default
    // (no subcommand) keeps the original `RustPEek <orig> <mod>` interface.
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "apply" {
        let mut clap_rest = vec![args[0].clone()]; // binary name
        clap_rest.extend_from_slice(&args[2..]);
        let cli = ApplyCli::parse_from(clap_rest);
        return apply_main(&cli);
    }
    let cli = DiffCli::parse();
    diff_main(&cli)
}

fn diff_main(cli: &DiffCli) -> Result<()> {
    let orig = pe_parser::load(&cli.original)?;
    let modif = pe_parser::load(&cli.modified)?;

    if let Some(pdb) = &orig.pdb_path {
        eprintln!("[!]  Original PE has embedded PDB: {}", pdb);
    }
    if let Some(pdb) = &modif.pdb_path {
        eprintln!("[!]  Modified PE has embedded PDB: {}", pdb);
    }

    if orig.raw_data.len() != modif.raw_data.len() {
        eprintln!(
            "Warning: file sizes differ ({} vs {} bytes). Comparing up to the shorter length.",
            orig.raw_data.len(),
            modif.raw_data.len()
        );
    }

    let mut entries = differ::compare(&orig, &modif, cli.context, cli.diff_only_headers);

    if let Some(ref sec) = cli.section {
        entries.retain(|e| e.section_name.eq_ignore_ascii_case(sec));
    }
    for ignored in &cli.ignore_section {
        entries.retain(|e| !e.section_name.eq_ignore_ascii_case(ignored));
    }
    if let Some(min) = cli.min_bytes {
        entries.retain(|e| e.original_bytes.len() >= min);
    }

    let semantic = semantic::analyze_semantic(&orig, &modif);

    match cli.format.as_str() {
        "csv" => {
            let data = output::to_csv(&entries);
            write_or_print(&cli.output, &data, entries.len())?;
        }
        "json" => {
            let data = output::to_json(&entries)?;
            write_or_print(&cli.output, &data, entries.len())?;
        }
        "patch" => {
            let out_path = cli
                .output
                .as_ref()
                .context("--output is required for 'patch' format")?;
            let patch_entries: Vec<&differ::DiffEntry> = entries.iter().collect();
            if out_path.ends_with(".ips") {
                let bytes = patch::to_ips(&patch_entries);
                fs::write(out_path, &bytes)
                    .with_context(|| format!("cannot write to '{out_path}'"))?;
                println!(
                    "IPS patch written to '{out_path}' ({} entries).",
                    patch_entries.len()
                );
            } else {
                let rp = patch::export_patch(&cli.original, &orig.raw_data, &patch_entries);
                let json = serde_json::to_string_pretty(&rp)?;
                fs::write(out_path, &json)
                    .with_context(|| format!("cannot write to '{out_path}'"))?;
                println!(
                    "RPK patch written to '{out_path}' ({} entries).",
                    patch_entries.len()
                );
            }
        }
        _ => {
            if let Some(ref path) = cli.output {
                let mut buf = String::new();
                plain_to_string(&cli.original, &cli.modified, &entries, &mut buf);
                fs::write(path, &buf).with_context(|| format!("cannot write to '{path}'"))?;
                println!("Report written to '{path}' ({} entries).", entries.len());
            } else {
                output::render_tui(
                    &cli.original,
                    &cli.modified,
                    &entries,
                    orig.is_64bit,
                    &semantic,
                    &orig.raw_data,
                )?;
            }
        }
    }

    Ok(())
}

fn apply_main(cli: &ApplyCli) -> Result<()> {
    let patch_path = PathBuf::from(&cli.patch);
    let target_path = PathBuf::from(&cli.target);
    let output_path = PathBuf::from(&cli.output);

    let count = patch::apply_patch(&patch_path, &target_path, &output_path, cli.force)?;

    println!(
        "Patched: {} -> {} ({} changes applied).",
        cli.target, cli.output, count
    );
    Ok(())
}

fn write_or_print(path: &Option<String>, data: &str, count: usize) -> Result<()> {
    match path {
        Some(p) => {
            fs::write(p, data).with_context(|| format!("cannot write to '{p}'"))?;
            println!("Report written to '{p}' ({count} entries).");
        }
        None => print!("{data}"),
    }
    Ok(())
}

fn plain_to_string(orig: &str, modif: &str, entries: &[differ::DiffEntry], buf: &mut String) {
    use std::fmt::Write;
    writeln!(buf, "PE Compare Report").unwrap();
    writeln!(buf, "Original : {orig}").unwrap();
    writeln!(buf, "Modified : {modif}").unwrap();
    writeln!(buf, "Total Diffs: {}", entries.len()).unwrap();
    writeln!(buf).unwrap();

    if entries.is_empty() {
        writeln!(buf, "No differences found.").unwrap();
        return;
    }

    let col_orig = entries
        .iter()
        .map(|e| output::fmt_bytes(&e.original_bytes).len())
        .max()
        .unwrap_or(14)
        .max(14);
    let col_mod = entries
        .iter()
        .map(|e| output::fmt_bytes(&e.modified_bytes).len())
        .max()
        .unwrap_or(14)
        .max(14);
    let col_sec = entries
        .iter()
        .map(|e| output::fmt_section(e).len())
        .max()
        .unwrap_or(7)
        .max(7);
    let col_pat = entries
        .iter()
        .map(|e| e.pattern_label.as_deref().unwrap_or("none").len())
        .max()
        .unwrap_or(8)
        .max(8);
    let col_ent = 10;

    let header = format!(
        "{:<10}   {:<14}   {:<13}   {:<orig$}   {:<modb$}   {:<sec$}   {:<pat$}   {:<ent$}",
        "RVA",
        "VA",
        "File Offset",
        "Original Bytes",
        "Modified Bytes",
        "Section",
        "Pattern",
        "Entropy Δ",
        orig = col_orig,
        modb = col_mod,
        sec = col_sec,
        pat = col_pat,
        ent = col_ent
    );
    writeln!(buf, "{header}").unwrap();
    writeln!(buf, "{}", "-".repeat(header.len())).unwrap();

    for e in entries {
        writeln!(
            buf,
            "{:<10}   {:<14}   {:<13}   {:<orig$}   {:<modb$}   {:<sec$}   {:<pat$}   {:>10.3}",
            format!("{:08X}", e.rva),
            format!("{:012X}", e.va),
            format!("{:08X}", e.file_offset),
            output::fmt_bytes(&e.original_bytes),
            output::fmt_bytes(&e.modified_bytes),
            output::fmt_section(e),
            e.pattern_label.as_deref().unwrap_or("none"),
            e.entropy_delta,
            orig = col_orig,
            modb = col_mod,
            sec = col_sec,
            pat = col_pat
        )
        .unwrap();
    }
}

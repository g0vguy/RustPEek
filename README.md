# RustPEek v0.3.0

A CLI tool that compares two Windows PE files byte‑by‑byte and presents the diff in an interactive terminal UI. Each changed region is shown with its RVA, VA, file offset, raw bytes, section name, **automatic patch pattern label**, **entropy delta**, and a **hex dump detail pane** with inline highlighting of changed bytes.

---

## Build

**Prerequisites:** Rust 1.86+ via [rustup](https://rustup.rs)

```bash
git clone https://github.com/g0vguy/RustPEek
cd RustPEek
cargo build --release
# binary: target/release/RustPEek.exe
```

---

## Usage

```
RustPEek <original> <modified> [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `-f, --format <table\|csv\|json>` | Output format (default: `table`) |
| `-o, --output <file>` | Write report to a file instead of opening the TUI |
| `-s, --section <name>` | Filter to a specific section, e.g. `.text` |
| `-b, --min-bytes <n>` | Only show diffs with ≥ N changed bytes |
| `-c, --context <n>` | Show N bytes of context before/after each diff region |
| `-i, --ignore-section <name>` | Exclude a section (repeatable, e.g. `.rsrc`) |
| `--diff-only-headers` | Compare PE headers only (skip section raw data) |

---

## Interactive TUI

Running without `--output` opens a full‑screen terminal UI.

```
RustPEek original.exe patched.exe
```

```
┌ RustPEek ──────────────────────────────────────────────────────────────────┐
│  Original : original.exe   Modified : patched.exe   Diffs: 3              │
└────────────────────────────────────────────────────────────────────────────┘
┌ Diff Results ──────────────────────────────────────────────────────────────┐
│ RVA          VA               File Offset    Original Bytes    Modified ... │
│─────────────────────────────────────────────────────────────────────────── │
│▶ 0144C99C    00018144C99C     0144BD9C       0F 84 28 0F 00    90 90 90 ... │
│  0144CA10    00018144CA10     0144BE10       74 05             90 90        │
│  00A3F120    000180A3F120     00A3E520       8B 45 08 83 C0    B8 01 00 ... │
└────────────────────────────────────────────────────────────────────────────┘
┌ Diff Detail ───────────────────────────────────────────────────────────────┐
│ Pattern: NOP sled   Entropy Δ: 0.012   (orig: 4.123  mod: 4.111)          │
│ 0000  0F 84 28 0F 00 00 00 00 00 00 00 00 00 00 00 00                    │
│      90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90                    │
└────────────────────────────────────────────────────────────────────────────┘
 ↑↓  navigate    /  search    y  copy row    e  export    q / Esc  quit
```

### Keybinds

| Key | Action |
|-----|--------|
| `↑` / `k` | Move up |
| `↓` / `j` | Move down |
| `g` / `Home` | Jump to first row |
| `G` / `End` | Jump to last row |
| `/` | Enter search mode — filter by section name, byte pattern, or patch label |
| `y` | Copy selected row to clipboard (includes all fields) |
| `e` | Export current view to a file |
| `q` / `Esc` | Quit |

Pressing `e` opens an inline filename prompt. Type a path and press `Enter` to write the file. The format is inferred from the extension — `.json`, `.csv`, or plain text for anything else. `Esc` cancels. A `✓ Exported` or `✗ Export failed` flash confirms the result.

Pressing `/` opens an inline search bar. The table filters live as you type, matching against section name, original bytes, modified bytes, and the detected patch pattern. The header shows `Filter: 'query' (n/total)`. `Enter` confirms, `Esc` clears.

Pressing `y` copies the selected row as tab‑separated values (includes RVA, VA, offset, bytes, section, pattern, and entropy delta) — pastes cleanly into Excel, Notepad, or IDA.

---

## File Export

Skip the TUI and write directly to a file:

```bash
# JSON
RustPEek orig.exe patched.exe --format json --output report.json

# CSV
RustPEek orig.exe patched.exe --format csv --output report.csv

# Plain text table
RustPEek orig.exe patched.exe --output report.txt
```

---

## Filtering & Context

```bash
# Only diffs inside .text
RustPEek orig.exe patched.exe --section .text

# Only runs of 4+ changed bytes
RustPEek orig.exe patched.exe --min-bytes 4

# Show 8 bytes of context around each diff
RustPEek orig.exe patched.exe --context 8

# Exclude noisy sections
RustPEek orig.exe patched.exe --ignore-section .rsrc --ignore-section .reloc

# Compare only headers (skip section data)
RustPEek orig.exe patched.exe --diff-only-headers

# Combine
RustPEek orig.exe patched.exe --section .text --context 4 --ignore-section .reloc
```

---

## Output Fields

| Field | Description | Example |
|-------|-------------|---------|
| RVA | Relative Virtual Address | `0144C99C` |
| VA | Virtual Address (ImageBase + RVA) | `00018144C99C` |
| File Offset | Raw byte offset from start of file | `0144BD9C` |
| Original Bytes | Hex bytes from the original file | `0F 84 28 0F 00 00` |
| Modified Bytes | Hex bytes from the modified file | `90 90 90 90 90 90` |
| Section | 1‑based index and name | `1\|.text` |
| Pattern | Detected patch pattern (if any) | `NOP sled`, `JMP near`, `RET` |
| Entropy Δ | Absolute difference in Shannon entropy between original and modified diff bytes | `0.012` |

Addresses outside any known section are shown as `?|unknown`.

When `--context <n>` is used, the bytes shown include N bytes before and after the changed region. The changed bytes sit in the middle.

---

## Project Structure

```
src/
├── main.rs       — CLI (clap v4), orchestration, PDB hint display
├── pe_parser.rs  — PE loading via goblin, section table extraction, PDB path parsing
├── address.rs    — FileOffset ↔ RVA ↔ VA conversions, section lookup
├── differ.rs     — byte comparison, contiguous run grouping, pattern detection, entropy calculation
└── output.rs     — ratatui TUI (with detail pane), CSV, JSON formatters
```

## Supported PE Formats

- PE32 (32‑bit)
- PE32+ / PE64 (64‑bit)

---

## New in v0.3.0

- **Patch pattern detection** – automatically labels common patterns like `NOP sled`, `JMP short/near`, `RET`, `RET imm`, etc.
- **Hex dump detail pane** – split view in the TUI showing original and modified hex bytes side‑by‑side, with changed bytes highlighted in yellow.
- **Entropy delta** – Shannon entropy of each diff region’s original and modified bytes; a large delta may suggest shellcode versus simple NOP padding.
- **PDB hint** – if a PE contains an embedded PDB path (RSDS CodeView), it is printed to stderr when loading.
- **`--diff-only-headers`** – compare only the PE headers (DOS header, NT headers, section headers) and skip raw section data; useful for quick structural checks.
- All export formats (plain, CSV, JSON) now include the new `Pattern` and `Entropy Δ` columns.

---

## Roadmap

- [x] `--context <n>` — show N bytes before/after each diff region
- [x] `--ignore-section <name>` — exclude noisy sections
- [x] `--diff-only-headers` — compare PE headers only
- [x] Patch pattern detection (`NOP sled`, `JMP patch`, `ret stub`)
- [x] Hex dump detail pane with changed bytes highlighted
- [x] Entropy delta per diff region
- [x] PDB hint on load

### Future Ideas

- [ ] Signature‑based recognition for common malware patching techniques
- [ ] Export diff as a binary patch file (`.patch`)
- [ ] Integration with IDA / Ghidra via script output

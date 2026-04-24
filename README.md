# RustPEek

A CLI tool that compares two Windows PE files byte-by-byte and presents the diff in an interactive terminal UI. Each changed region is shown with its RVA, VA, file offset, raw bytes, and section name.

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

---

## Interactive TUI

Running without `--output` opens a full-screen terminal UI.

```
RustPEek original.exe patched.exe
```

```
┌ RustPEek ──────────────────────────────────────────────────────────────────┐
│  Original : original.exe   Modified : patched.exe   Diffs: 3               │
└────────────────────────────────────────────────────────────────────────────┘
┌ Diff Results ──────────────────────────────────────────────────────────────┐
│ RVA          VA               File Offset    Original Bytes    Modified ... │
│─────────────────────────────────────────────────────────────────────────── │
│▶ 0144C99C    00018144C99C     0144BD9C       0F 84 28 0F 00    90 90 90 ... │
│  0144CA10    00018144CA10     0144BE10       74 05             90 90        │
│  00A3F120    000180A3F120     00A3E520       8B 45 08 83 C0    B8 01 00 ... │
└────────────────────────────────────────────────────────────────────────────┘
 ↑↓  navigate    y  copy row    q / Esc  quit
```

### Keybinds

| Key | Action |
|-----|--------|
| `↑` / `k` | Move up |
| `↓` / `j` | Move down |
| `g` / `Home` | Jump to first row |
| `G` / `End` | Jump to last row |
| `y` | Copy selected row to clipboard |
| `q` / `Esc` | Quit |

Pressing `y` copies the selected row as tab-separated values — pastes cleanly into Excel, Notepad, or IDA.

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

## Filtering

```bash
# Only diffs inside .text
RustPEek orig.exe patched.exe --section .text

# Only runs of 4+ changed bytes
RustPEek orig.exe patched.exe --min-bytes 4

# Combine both
RustPEek orig.exe patched.exe --section .text --min-bytes 4
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
| Section | 1-based index and name | `1\|.text` |

Addresses outside any known section are shown as `?|unknown`.

---

## Project Structure

```
src/
├── main.rs       — CLI (clap v4), orchestration
├── pe_parser.rs  — PE loading via goblin, section table extraction
├── address.rs    — FileOffset ↔ RVA ↔ VA conversions, section lookup
├── differ.rs     — byte comparison, contiguous run grouping
└── output.rs     — ratatui TUI, CSV, JSON formatters
```

## Supported PE Formats

- PE32 (32-bit)
- PE32+ / PE64 (64-bit)

---

## TODO
- [ ] `--context <n>` — show N bytes before/after each diff region
- [ ] `--ignore-section <name>` — exclude noisy sections like `.rsrc` or `.reloc`
- [ ] Patch pattern detection — automatically label common patterns (`NOP sled`, `JMP patch`, `ret stub`)
- [ ] Hex dump detail pane — split view showing a hex dump of the selected region with changed bytes highlighted inline
- [ ] `/` search — filter rows by section name or byte pattern without leaving the TUI
- [ ] `e` export — save the current filtered view to a file from inside the TUI
- [ ] Entropy delta per diff region — flags whether a patch looks like shellcode vs a simple NOP
- [ ] PDB hint — if a PDB path is embedded in the PE, surface it so the user knows symbols are available
- [ ] `--diff-only-headers` — compare PE headers only, skip section data

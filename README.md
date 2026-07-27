# RustPEek v0.4.0

A CLI tool that compares two Windows PE files byte‑by‑byte and presents the diff in an interactive terminal UI. Each changed region is shown with its RVA, VA, file offset, raw bytes, section name, **automatic patch pattern label**, **entropy delta**, a **hex dump detail pane**, **inline disassembly**, and a **semantic diff view** for imports, exports, and resources. Diffs can be exported as `.rpk` or `.ips` binary patch files and applied to other files.

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
RustPEek apply <patch> <target> <output> [--force]
```

### Diff flags

| Flag | Description |
|------|-------------|
| `-f, --format <table|csv|json|patch>` | Output format (default: `table`) |
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
│▶ 0144C99C    00018144C99C     0144BD9C       0F 84 28 0F 00    90 90 90 ... │
│  0144CA10    00018144CA10     0144BE10       74 05             90 90        │
│  00A3F120    000180A3F120     00A3E520       8B 45 08 83 C0    B8 01 00 ... │
└────────────────────────────────────────────────────────────────────────────┘
┌ Diff Detail ───────────────────────────────────────────────────────────────┐
│ Pattern: NOP sled   Entropy Δ: 0.012   orig: 4.123  mod: 4.111            │
│ 0000  0F 84 28 0F 00 00 00 00 00 00 00 00 00 00 00 00                     │
│       90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90                     │
└────────────────────────────────────────────────────────────────────────────┘
┌ Disassembly ───────────────────────────────────────────────────────────────┐
│ 00018144C99C  jz 0x18144d8cah                  │ nop                       │
└────────────────────────────────────────────────────────────────────────────┘
 ↑↓ navigate    / search    y copy    d disasm    e export    p patch    Tab semantic    q / Esc quit
```

### Keybinds

| Key | Action |
|-----|--------|
| `↑` / `k` | Move up |
| `↓` / `j` | Move down |
| `g` / `Home` | Jump to first row |
| `G` / `End` | Jump to last row |
| `/` | Enter search mode — filter by section name, byte pattern, or patch label |
| `y` | Copy selected row to clipboard (tab-separated, pastes into Excel / IDA) |
| `d` | Toggle the disassembly pane on/off |
| `e` | Export current view to a file (`.json`, `.csv`, or plain text) |
| `p` | Export current diff as a binary patch file (`.rpk` or `.ips`) |
| `Tab` | Toggle between Byte Diff view and Semantic Diff view |
| `q` / `Esc` | Quit |


---

## Disassembly Pane

The disassembly pane shows the decoded instructions for the selected diff region side‑by‑side:

```
┌ Disassembly ───────────────────────────────────────────────┐
│ 00018144C99C  jz 0x18144d8cah    │ nop                     │  ← yellow (changed)
│ 00018144C9A2  xor eax,eax        │ xor eax,eax             │  ← gray (unchanged)
└────────────────────────────────────────────────────────────┘
```

- Changed instructions are highlighted in **yellow**
- Unchanged instructions are shown in **dim gray**
- Uses NASM syntax via `iced-x86`
- Press `d` to hide/show the pane

---

## Semantic Diff View

Press `Tab` to switch to the Semantic Diff view, which compares PE structures rather than raw bytes:

```
┌ Semantic Changes ──────────────────────────────────────────┐
│ Category   Change       Detail                             │
│ Import     Added        kernel32.dll!VirtualAlloc          │
│ Import     Removed      advapi32.dll!RegOpenKeyExW         │
│ Export     Forwarded    ord=5 -> ntdll.RtlGetVersion       │
│ Resource   Modified     RT_MANIFEST changed                │
└────────────────────────────────────────────────────────────┘
```

Detects:
- **Imports** added or removed
- **Exports** added, removed, or newly forwarded
- **Resources** added, removed, or changed in size
- `RT_MANIFEST` and `RT_VERSION` changes flagged specifically

---

## Binary Patch Export & Apply

### Export from TUI
Press `p` in the TUI to export the current diff as a patch file.

### Export from CLI
```bash
# RPK patch (JSON)
RustPEek orig.exe patched.exe --format patch --output fix.rpk

# IPS patch
RustPEek orig.exe patched.exe --format patch --output fix.ips
```

### Apply a patch
```bash
RustPEek apply fix.rpk target.exe output.exe

# Skip SHA-256 verification
RustPEek apply fix.rpk target.exe output.exe --force
```

The `apply` subcommand:
1. Verifies `sha256(target)` matches the patch's recorded hash (unless `--force`)
2. Verifies each patch entry's original bytes match the target at the given offset
3. Applies all patches and writes the result to `output`
4. Prints `Patched: target.exe -> output.exe (N changes applied)`

### RPK format
```json
{
  "version": 1,
  "target_filename": "IDMan.exe",
  "target_size": 12345678,
  "target_sha256": "abc123...",
  "patches": [
    {
      "file_offset": 315296,
      "original_bytes": [131, 224, 15, 131, 192, 15],
      "patched_bytes": [184, 255, 255, 255, 127, 144],
      "description": "NOP sled"
    }
  ]
}
```

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
├── main.rs       — CLI (clap v4), orchestration, PDB hint display, apply subcommand
├── pe_parser.rs  — PE loading via goblin, section table, imports, exports, PDB path, is_64bit
├── address.rs    — FileOffset ↔ RVA ↔ VA conversions, section lookup
├── differ.rs     — byte comparison, contiguous run grouping, pattern detection, entropy calculation
├── disasm.rs     — inline disassembly via iced-x86, VA-aligned orig/mod instruction pairing
├── semantic.rs   — import/export/resource structural diffing via goblin + pelite
├── patch.rs      — RPK and IPS patch format, export_patch(), apply_patch(), to_ips()
└── output.rs     — ratatui TUI, CSV/JSON formatters
```

## Supported PE Formats

- PE32 (32‑bit)
- PE32+ / PE64 (64‑bit)

---

## Roadmap

- [x] `--context <n>` — show N bytes before/after each diff region
- [x] `--ignore-section <name>` — exclude noisy sections
- [x] `--diff-only-headers` — compare PE headers only
- [x] Patch pattern detection (`NOP sled`, `JMP patch`, `ret stub`)
- [x] Hex dump detail pane with changed bytes highlighted
- [x] Entropy delta per diff region
- [x] PDB hint on load
- [x] Inline disassembly pane (iced-x86, NASM syntax, `d` to toggle)
- [x] Semantic diff view — imports, exports, resources (`Tab` to toggle)
- [x] Binary patch export — `.rpk` JSON and `.ips` IPS formats (`p` keybind)
- [x] `--format patch` CLI export for RPK and IPS
- [x] `RustPEek apply` — apply `.rpk` patches with SHA-256 + byte verification

### Future Ideas

- [ ] Integration with IDA / Ghidra via script output
- [ ] Scrolling in the disassembly and detail panes

use crate::differ::DiffEntry;
use anyhow::Result;
use cli_clipboard::ClipboardProvider;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
    Terminal,
};
use std::io;
use std::time::{Duration, Instant};

#[derive(PartialEq)]
enum InputMode {
    Normal,
    Search,
    Export,
}

pub fn fmt_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
}

pub fn fmt_section(entry: &DiffEntry) -> String {
    if entry.section_index == 0 {
        "?|unknown".to_string()
    } else {
        format!("{}|{}", entry.section_index, entry.section_name)
    }
}

pub fn render_tui(orig_path: &str, mod_path: &str, entries: &[DiffEntry]) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = TableState::default();
    if !entries.is_empty() {
        state.select(Some(0));
    }

    let result = run_tui(&mut terminal, &mut state, orig_path, mod_path, entries);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn entry_to_clipboard(e: &DiffEntry) -> String {
    format!(
        "{:08X}\t{:012X}\t{:08X}\t{}\t{}\t{}",
        e.rva, e.va, e.file_offset,
        fmt_bytes(&e.original_bytes),
        fmt_bytes(&e.modified_bytes),
        fmt_section(e),
    )
}

fn run_tui(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &mut TableState,
    orig_path: &str,
    mod_path: &str,
    entries: &[DiffEntry],
) -> Result<()> {
    let mut copied_at: Option<Instant> = None;
    let mut search = String::new();
    let mut export_path = String::new();
    let mut mode = InputMode::Normal;
    let mut status: Option<(String, Instant, bool)> = None; // (msg, time, success)

    let header_cells = ["RVA", "VA", "File Offset", "Original Bytes", "Modified Bytes", "Section"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1).bottom_margin(0);

    let widths = [
        Constraint::Length(10),
        Constraint::Length(14),
        Constraint::Length(13),
        Constraint::Min(20),
        Constraint::Min(20),
        Constraint::Length(16),
    ];

    loop {
        let needle = search.to_ascii_lowercase();
        let visible: Vec<&DiffEntry> = entries
            .iter()
            .filter(|e| {
                if needle.is_empty() {
                    return true;
                }
                let sec = fmt_section(e).to_ascii_lowercase();
                let orig_hex = fmt_bytes(&e.original_bytes).to_ascii_lowercase();
                let mod_hex  = fmt_bytes(&e.modified_bytes).to_ascii_lowercase();
                sec.contains(&needle) || orig_hex.contains(&needle) || mod_hex.contains(&needle)
            })
            .collect();

        let rows: Vec<Row> = visible
            .iter()
            .map(|e| {
                Row::new([
                    Cell::from(format!("{:08X}", e.rva)).style(Style::default().fg(Color::Yellow)),
                    Cell::from(format!("{:012X}", e.va)).style(Style::default().fg(Color::Yellow)),
                    Cell::from(format!("{:08X}", e.file_offset)).style(Style::default().fg(Color::White)),
                    Cell::from(fmt_bytes(&e.original_bytes)).style(Style::default().fg(Color::Red)),
                    Cell::from(fmt_bytes(&e.modified_bytes)).style(Style::default().fg(Color::Green)),
                    Cell::from(fmt_section(e)).style(Style::default().fg(Color::Magenta)),
                ])
            })
            .collect();

        if state.selected().map(|i| i >= visible.len()).unwrap_or(false) {
            state.select(if visible.is_empty() { None } else { Some(visible.len().saturating_sub(1)) });
        }

        terminal.draw(|f| {
            let area = f.area();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(1)])
                .split(area);

            let filter_info = if !needle.is_empty() {
                format!("   Filter: '{}' ({}/{})", search, visible.len(), entries.len())
            } else {
                format!("   Diffs: {}", entries.len())
            };

            let title = Paragraph::new(Line::from(vec![
                Span::styled("  Original : ", Style::default().fg(Color::DarkGray)),
                Span::styled(orig_path, Style::default().fg(Color::White)),
                Span::styled("   Modified : ", Style::default().fg(Color::DarkGray)),
                Span::styled(mod_path, Style::default().fg(Color::White)),
                Span::styled(filter_info, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            ]))
            .block(Block::default().borders(Borders::ALL).title(Span::styled(
                " RustPEek ",
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )));

            let table = Table::new(rows, widths)
                .header(header.clone())
                .block(Block::default().borders(Borders::ALL).title(" Diff Results "))
                .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
                .highlight_symbol("▶ ");

            let copied_visible = copied_at.map(|t| t.elapsed() < Duration::from_secs(2)).unwrap_or(false);

            let help = match mode {
                InputMode::Search => Paragraph::new(Line::from(vec![
                    Span::styled(" / ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                    Span::styled(&search, Style::default().fg(Color::White)),
                    Span::styled("█", Style::default().fg(Color::Yellow)),
                    Span::styled("   Enter ", Style::default().fg(Color::DarkGray)),
                    Span::raw("confirm   "),
                    Span::styled(" Esc ", Style::default().fg(Color::DarkGray)),
                    Span::raw("clear"),
                ])),
                InputMode::Export => Paragraph::new(Line::from(vec![
                    Span::styled(" e ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                    Span::styled(&export_path, Style::default().fg(Color::White)),
                    Span::styled("█", Style::default().fg(Color::Yellow)),
                    Span::styled("   Enter ", Style::default().fg(Color::DarkGray)),
                    Span::raw("save   "),
                    Span::styled(" Esc ", Style::default().fg(Color::DarkGray)),
                    Span::raw("cancel"),
                ])),
                InputMode::Normal => {
                    let status_span = if let Some((ref msg, t, ok)) = status {
                        if t.elapsed() < Duration::from_secs(2) {
                            let color = if ok { Color::Green } else { Color::Red };
                            Span::styled(format!("   {msg}"), Style::default().fg(color).add_modifier(Modifier::BOLD))
                        } else { Span::raw("") }
                    } else if copied_visible {
                        Span::styled("   ✓ Copied!", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
                    } else {
                        Span::raw("")
                    };
                    Paragraph::new(Line::from(vec![
                        Span::styled(" ↑↓ ", Style::default().fg(Color::Cyan)),
                        Span::raw("navigate   "),
                        Span::styled(" / ", Style::default().fg(Color::Cyan)),
                        Span::raw("search   "),
                        Span::styled(" y ", Style::default().fg(Color::Cyan)),
                        Span::raw("copy   "),
                        Span::styled(" e ", Style::default().fg(Color::Cyan)),
                        Span::raw("export   "),
                        Span::styled(" q / Esc ", Style::default().fg(Color::Cyan)),
                        Span::raw("quit"),
                        status_span,
                    ]))
                }
            };

            f.render_widget(title, chunks[0]);
            f.render_stateful_widget(table, chunks[1], state);
            f.render_widget(help, chunks[2]);
        })?;

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match mode {
                InputMode::Search => match key.code {
                    KeyCode::Esc => {
                        search.clear();
                        mode = InputMode::Normal;
                        state.select(if entries.is_empty() { None } else { Some(0) });
                    }
                    KeyCode::Enter => { mode = InputMode::Normal; }
                    KeyCode::Backspace => { search.pop(); }
                    KeyCode::Char(c) => { search.push(c); }
                    _ => {}
                },
                InputMode::Export => match key.code {
                    KeyCode::Esc => {
                        export_path.clear();
                        mode = InputMode::Normal;
                    }
                    KeyCode::Enter => {
                        let path = export_path.trim().to_string();
                        if !path.is_empty() {
                            let owned: Vec<DiffEntry> = visible.iter().map(|e| (*e).clone()).collect();
                            let content = if path.ends_with(".json") {
                                to_json(&owned).ok()
                            } else if path.ends_with(".csv") {
                                Some(to_csv(&owned))
                            } else {
                                Some(render_plain(orig_path, mod_path, visible.as_slice()))
                            };
                            let (msg, ok) = match content.map(|c| std::fs::write(&path, c)) {
                                Some(Ok(())) => (format!("✓ Exported to {path}"), true),
                                _ => (format!("✗ Export failed: {path}"), false),
                            };
                            status = Some((msg, Instant::now(), ok));
                        }
                        export_path.clear();
                        mode = InputMode::Normal;
                    }
                    KeyCode::Backspace => { export_path.pop(); }
                    KeyCode::Char(c) => { export_path.push(c); }
                    _ => {}
                },
                InputMode::Normal => match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('/') => {
                        mode = InputMode::Search;
                        state.select(if visible.is_empty() { None } else { Some(0) });
                    }
                    KeyCode::Char('e') => {
                        export_path.clear();
                        mode = InputMode::Export;
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        let next = state.selected().map(|i| (i + 1).min(visible.len().saturating_sub(1))).unwrap_or(0);
                        state.select(Some(next));
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        let prev = state.selected().map(|i| i.saturating_sub(1)).unwrap_or(0);
                        state.select(Some(prev));
                    }
                    KeyCode::Home | KeyCode::Char('g') => state.select(Some(0)),
                    KeyCode::End | KeyCode::Char('G') => {
                        state.select(Some(visible.len().saturating_sub(1)));
                    }
                    KeyCode::Char('y') => {
                        if let Some(i) = state.selected() {
                            if let Some(e) = visible.get(i) {
                                let text = entry_to_clipboard(e);
                                if let Ok(mut ctx) = cli_clipboard::ClipboardContext::new() {
                                    let _ = ctx.set_contents(text);
                                    copied_at = Some(Instant::now());
                                }
                            }
                        }
                    }
                    _ => {}
                },
            }
        }
    }
    Ok(())
}

fn render_plain(orig_path: &str, mod_path: &str, entries: &[&DiffEntry]) -> String {
    use std::fmt::Write;
    let mut buf = String::new();
    writeln!(buf, "RustPEek Export").unwrap();
    writeln!(buf, "Original : {orig_path}").unwrap();
    writeln!(buf, "Modified : {mod_path}").unwrap();
    writeln!(buf, "Total Diffs: {}", entries.len()).unwrap();
    writeln!(buf).unwrap();
    if entries.is_empty() {
        writeln!(buf, "No differences found.").unwrap();
        return buf;
    }
    let col_orig = entries.iter().map(|e| fmt_bytes(&e.original_bytes).len()).max().unwrap_or(14).max(14);
    let col_mod  = entries.iter().map(|e| fmt_bytes(&e.modified_bytes).len()).max().unwrap_or(14).max(14);
    let col_sec  = entries.iter().map(|e| fmt_section(e).len()).max().unwrap_or(7).max(7);
    let header = format!(
        "{:<10}   {:<14}   {:<13}   {:<orig$}   {:<modb$}   {:<sec$}",
        "RVA", "VA", "File Offset", "Original Bytes", "Modified Bytes", "Section",
        orig = col_orig, modb = col_mod, sec = col_sec
    );
    writeln!(buf, "{header}").unwrap();
    writeln!(buf, "{}", "-".repeat(header.len())).unwrap();
    for e in entries {
        writeln!(
            buf,
            "{:<10}   {:<14}   {:<13}   {:<orig$}   {:<modb$}   {:<sec$}",
            format!("{:08X}", e.rva), format!("{:012X}", e.va), format!("{:08X}", e.file_offset),
            fmt_bytes(&e.original_bytes), fmt_bytes(&e.modified_bytes), fmt_section(e),
            orig = col_orig, modb = col_mod, sec = col_sec
        ).unwrap();
    }
    buf
}

pub fn to_csv(entries: &[DiffEntry]) -> String {
    let mut out = String::from("\"RVA\",\"VA\",\"File Offset\",\"Original Bytes\",\"Modified Bytes\",\"Section\"\n");
    for e in entries {
        out.push_str(&format!(
            "\"{:08X}\",\"{:012X}\",\"{:08X}\",\"{}\",\"{}\",\"{}\"\n",
            e.rva, e.va, e.file_offset,
            fmt_bytes(&e.original_bytes),
            fmt_bytes(&e.modified_bytes),
            fmt_section(e),
        ));
    }
    out
}

pub fn to_json(entries: &[DiffEntry]) -> Result<String> {
    #[derive(serde::Serialize)]
    struct Row {
        rva: String,
        va: String,
        file_offset: String,
        original_bytes: String,
        modified_bytes: String,
        section: String,
    }

    let rows: Vec<Row> = entries
        .iter()
        .map(|e| Row {
            rva: format!("{:08X}", e.rva),
            va: format!("{:012X}", e.va),
            file_offset: format!("{:08X}", e.file_offset),
            original_bytes: fmt_bytes(&e.original_bytes),
            modified_bytes: fmt_bytes(&e.modified_bytes),
            section: fmt_section(e),
        })
        .collect();

    Ok(serde_json::to_string_pretty(&rows)?)
}


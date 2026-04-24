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
    let header_cells = ["RVA", "VA", "File Offset", "Original Bytes", "Modified Bytes", "Section"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1).bottom_margin(0);

    let rows: Vec<Row> = entries
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

    let widths = [
        Constraint::Length(10),
        Constraint::Length(14),
        Constraint::Length(13),
        Constraint::Min(20),
        Constraint::Min(20),
        Constraint::Length(16),
    ];

    loop {
        terminal.draw(|f| {
            let area = f.area();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(1)])
                .split(area);

            let title = Paragraph::new(vec![
                Line::from(vec![
                    Span::styled("  Original : ", Style::default().fg(Color::DarkGray)),
                    Span::styled(orig_path, Style::default().fg(Color::White)),
                    Span::styled("   Modified : ", Style::default().fg(Color::DarkGray)),
                    Span::styled(mod_path, Style::default().fg(Color::White)),
                    Span::styled(
                        format!("   Diffs: {}", entries.len()),
                        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                    ),
                ]),
            ])
            .block(Block::default().borders(Borders::ALL).title(Span::styled(
                " RustPEek ",
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )));

            let table = Table::new(rows.clone(), widths)
                .header(header.clone())
                .block(Block::default().borders(Borders::ALL).title(" Diff Results "))
                .highlight_style(
                    Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD),
                )
                .highlight_symbol("▶ ");

            let copied_visible = copied_at.map(|t| t.elapsed() < Duration::from_secs(2)).unwrap_or(false);
            let help = Paragraph::new(Line::from(vec![
                Span::styled(" ↑↓ ", Style::default().fg(Color::Cyan)),
                Span::raw("navigate   "),
                Span::styled(" y ", Style::default().fg(Color::Cyan)),
                Span::raw("copy row   "),
                Span::styled(" q / Esc ", Style::default().fg(Color::Cyan)),
                Span::raw("quit"),
                if copied_visible {
                    Span::styled("   ✓ Copied!", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
                } else {
                    Span::raw("")
                },
            ]));

            f.render_widget(title, chunks[0]);
            f.render_stateful_widget(table, chunks[1], state);
            f.render_widget(help, chunks[2]);
        })?;

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Down | KeyCode::Char('j') => {
                    let next = state.selected().map(|i| (i + 1).min(entries.len().saturating_sub(1))).unwrap_or(0);
                    state.select(Some(next));
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    let prev = state.selected().map(|i| i.saturating_sub(1)).unwrap_or(0);
                    state.select(Some(prev));
                }
                KeyCode::Home | KeyCode::Char('g') => state.select(Some(0)),
                KeyCode::End | KeyCode::Char('G') => {
                    state.select(Some(entries.len().saturating_sub(1)));
                }
                KeyCode::Char('y') => {
                    if let Some(i) = state.selected() {
                        let text = entry_to_clipboard(&entries[i]);
                        if let Ok(mut ctx) = cli_clipboard::ClipboardContext::new() {
                            let _ = ctx.set_contents(text);
                            copied_at = Some(Instant::now());
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
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


//! A live terminal UI for the scanner, built on [`ratatui`].
//!
//! The scan runs on a background thread so the interface stays responsive; a
//! channel delivers the results back to the render loop. Keys: `r` rescans,
//! `/` filters across every field, the arrow keys move the selection, and `q`
//! quits.

use crate::scan::{Host, ScanConfig, scan};

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Layout, Margin};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState};
use ratatui::{DefaultTerminal, Frame};

use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

/// The mutable state driving the TUI.
struct App {
    cfg: ScanConfig,
    hosts: Vec<Host>,
    scanning: bool,
    selected: TableState,
    /// Current filter text; empty means show everything.
    filter: String,
    /// True while the user is typing into the filter.
    input_mode: bool,
    results_rx: Receiver<Vec<Host>>,
    results_tx: Sender<Vec<Host>>,
}

impl App {
    fn new(cfg: ScanConfig) -> Self {
        let (tx, rx) = mpsc::channel();
        let mut app = Self {
            cfg,
            hosts: Vec::new(),
            scanning: false,
            selected: TableState::default(),
            filter: String::new(),
            input_mode: false,
            results_rx: rx,
            results_tx: tx,
        };
        app.start_scan();
        app
    }

    /// Hosts matching the current filter, in display order.
    fn visible(&self) -> Vec<&Host> {
        self.hosts
            .iter()
            .filter(|h| h.matches(&self.filter))
            .collect()
    }

    /// Keep the selection within the visible rows, selecting the first row when
    /// nothing is selected but matches exist.
    fn clamp_selection(&mut self) {
        let len = self.visible().len();
        if len == 0 {
            self.selected.select(None);
        } else {
            let current = self.selected.selected().unwrap_or(0);
            self.selected.select(Some(current.min(len - 1)));
        }
    }

    /// Spawn a background scan; results arrive on `results_rx`.
    fn start_scan(&mut self) {
        if self.scanning {
            return;
        }
        self.scanning = true;
        let cfg = self.cfg.clone();
        let tx = self.results_tx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(scan(&cfg));
        });
    }

    /// Drain any completed scan into the host list.
    fn poll_results(&mut self) {
        while let Ok(hosts) = self.results_rx.try_recv() {
            self.hosts = hosts;
            self.scanning = false;
        }
        if self.selected.selected().is_none() && !self.visible().is_empty() {
            self.selected.select(Some(0));
        }
        self.clamp_selection();
    }

    fn move_selection(&mut self, delta: isize) {
        let len = self.visible().len();
        if len == 0 {
            return;
        }
        let current = self.selected.selected().unwrap_or(0) as isize;
        let next = (current + delta).rem_euclid(len as isize) as usize;
        self.selected.select(Some(next));
    }
}

/// Launch the TUI, scanning `cfg`. Restores the terminal on exit even on error.
///
/// # Errors
///
/// Propagates terminal or event I/O errors.
pub fn run(cfg: ScanConfig) -> std::io::Result<()> {
    let mut terminal = ratatui::init();
    let result = run_loop(&mut terminal, App::new(cfg));
    ratatui::restore();
    result
}

fn run_loop(terminal: &mut DefaultTerminal, mut app: App) -> std::io::Result<()> {
    loop {
        app.poll_results();
        terminal.draw(|frame| draw(frame, &mut app))?;

        // Poll briefly so background results render promptly.
        if event::poll(Duration::from_millis(150))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                if app.input_mode {
                    // While typing, keys edit the filter rather than run commands.
                    match key.code {
                        KeyCode::Enter => app.input_mode = false,
                        KeyCode::Esc => {
                            app.input_mode = false;
                            app.filter.clear();
                        }
                        KeyCode::Backspace => {
                            app.filter.pop();
                        }
                        KeyCode::Char(c) => app.filter.push(c),
                        _ => {}
                    }
                    // Re-anchor the selection to the first match as the filter changes.
                    app.selected.select(None);
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Esc => {
                        // Esc clears an active filter first, then quits.
                        if app.filter.is_empty() {
                            return Ok(());
                        }
                        app.filter.clear();
                        app.selected.select(None);
                    }
                    KeyCode::Char('/') => app.input_mode = true,
                    KeyCode::Char('r') => app.start_scan(),
                    KeyCode::Down | KeyCode::Char('j') => app.move_selection(1),
                    KeyCode::Up | KeyCode::Char('k') => app.move_selection(-1),
                    _ => {}
                }
            }
        }
    }
}

fn draw(frame: &mut Frame, app: &mut App) {
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(3),
        Constraint::Length(3),
    ])
    .split(frame.area());

    draw_header(frame, app, chunks[0]);
    draw_table(frame, app, chunks[1]);
    draw_footer(frame, chunks[2], app);
}

fn draw_header(frame: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let status = if app.scanning { "scanning..." } else { "done" };
    let shown = app.visible().len();
    let count = if app.filter.is_empty() {
        format!("{} host(s)   ", app.hosts.len())
    } else {
        format!("{shown}/{} host(s)   ", app.hosts.len())
    };
    let mut spans = vec![
        " LAN Scan ".bold().bg(Color::Cyan).fg(Color::Black),
        format!("  {}   ", app.cfg.cidr).into(),
        count.fg(Color::Green),
        format!("[{status}]").fg(if app.scanning {
            Color::Yellow
        } else {
            Color::DarkGray
        }),
    ];
    if app.input_mode || !app.filter.is_empty() {
        let cursor = if app.input_mode { "_" } else { "" };
        spans.push(format!("   filter: {}{cursor}", app.filter).fg(Color::Cyan));
    }
    let block = Block::default().borders(Borders::ALL).title(" lanscan ");
    frame.render_widget(Paragraph::new(Line::from(spans)).block(block), area);
}

fn draw_table(frame: &mut Frame, app: &mut App, area: ratatui::layout::Rect) {
    let header = Row::new(["IP", "MAC", "HOSTNAME", "VENDOR", "OPEN PORTS"]).style(
        Style::default()
            .add_modifier(Modifier::BOLD)
            .fg(Color::Cyan),
    );

    let rows: Vec<Row> = app
        .visible()
        .into_iter()
        .map(|host| {
            let ports = if host.open_ports.is_empty() {
                "-".to_string()
            } else {
                host.open_ports
                    .iter()
                    .map(|p| p.service.clone().unwrap_or_else(|| p.port.to_string()))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            Row::new(vec![
                Cell::from(host.ip.to_string()),
                Cell::from(host.mac.clone().unwrap_or_else(|| "-".into())),
                Cell::from(host.hostname.clone().unwrap_or_else(|| "-".into())),
                Cell::from(host.vendor.clone().unwrap_or_else(|| "-".into())),
                Cell::from(ports),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(16),
        Constraint::Length(18),
        Constraint::Length(22),
        Constraint::Length(18),
        Constraint::Min(20),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(" hosts "))
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    frame.render_stateful_widget(table, area, &mut app.selected);

    if app.visible().is_empty() && !app.scanning {
        let message = if app.hosts.is_empty() {
            "No live hosts found. Press 'r' to rescan."
        } else {
            "No hosts match the filter. Press Esc to clear."
        };
        let hint = Paragraph::new(message).fg(Color::DarkGray).centered();
        frame.render_widget(
            hint,
            area.inner(Margin {
                horizontal: 2,
                vertical: 2,
            }),
        );
    }
}

fn draw_footer(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let line = if app.input_mode {
        Line::from(vec![
            " type ".bg(Color::Cyan).fg(Color::Black),
            " filter   ".into(),
            " Enter ".bg(Color::Cyan).fg(Color::Black),
            " apply   ".into(),
            " Esc ".bg(Color::Cyan).fg(Color::Black),
            " clear ".into(),
        ])
    } else {
        Line::from(vec![
            " r ".bg(Color::Cyan).fg(Color::Black),
            " rescan   ".into(),
            " / ".bg(Color::Cyan).fg(Color::Black),
            " filter   ".into(),
            " up/down ".bg(Color::Cyan).fg(Color::Black),
            " select   ".into(),
            " q ".bg(Color::Cyan).fg(Color::Black),
            " quit ".into(),
        ])
    };
    frame.render_widget(
        Paragraph::new(line).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

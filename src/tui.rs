//! A live terminal UI for the scanner, built on [`ratatui`].
//!
//! The scan runs on a background thread so the interface stays responsive; a
//! channel delivers the results back to the render loop. Keys: `r` rescans,
//! `q`/`Esc` quits, and the arrow keys move the selection.

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
            results_rx: rx,
            results_tx: tx,
        };
        app.start_scan();
        app
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
            if self.hosts.is_empty() {
                self.selected.select(None);
            } else {
                self.selected.select(Some(0));
            }
        }
    }

    fn move_selection(&mut self, delta: isize) {
        if self.hosts.is_empty() {
            return;
        }
        let len = self.hosts.len();
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
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
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
    draw_footer(frame, chunks[2]);
}

fn draw_header(frame: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let status = if app.scanning { "scanning..." } else { "done" };
    let line = Line::from(vec![
        " LAN Scan ".bold().bg(Color::Cyan).fg(Color::Black),
        format!("  {}   ", app.cfg.cidr).into(),
        format!("{} host(s)   ", app.hosts.len()).fg(Color::Green),
        format!("[{status}]").fg(if app.scanning {
            Color::Yellow
        } else {
            Color::DarkGray
        }),
    ]);
    let block = Block::default().borders(Borders::ALL).title(" lanscan ");
    frame.render_widget(Paragraph::new(line).block(block), area);
}

fn draw_table(frame: &mut Frame, app: &mut App, area: ratatui::layout::Rect) {
    let header = Row::new(["IP", "HOSTNAME", "VENDOR", "OPEN PORTS"]).style(
        Style::default()
            .add_modifier(Modifier::BOLD)
            .fg(Color::Cyan),
    );

    let rows: Vec<Row> = app
        .hosts
        .iter()
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
                Cell::from(host.hostname.clone().unwrap_or_else(|| "-".into())),
                Cell::from(host.vendor.clone().unwrap_or_else(|| "-".into())),
                Cell::from(ports),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(16),
        Constraint::Length(24),
        Constraint::Length(20),
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

    if app.hosts.is_empty() && !app.scanning {
        let hint = Paragraph::new("No live hosts found. Press 'r' to rescan.")
            .fg(Color::DarkGray)
            .centered();
        frame.render_widget(
            hint,
            area.inner(Margin {
                horizontal: 2,
                vertical: 2,
            }),
        );
    }
}

fn draw_footer(frame: &mut Frame, area: ratatui::layout::Rect) {
    let line = Line::from(vec![
        " r ".bg(Color::Cyan).fg(Color::Black),
        " rescan   ".into(),
        " up/down ".bg(Color::Cyan).fg(Color::Black),
        " select   ".into(),
        " q ".bg(Color::Cyan).fg(Color::Black),
        " quit ".into(),
    ]);
    frame.render_widget(
        Paragraph::new(line).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

// =============================================================================
// netwatch-tui — Terminal UI for monitoring active TCP connections in real time.
//
// This is a thin display layer on top of netwatch-core, which handles all
// polling, parsing, whois lookups, and connection tracking.
// =============================================================================

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Cell, Row, Table, TableState},
    Frame, Terminal,
};
use std::{
    io::{self, stdout},
    time::{Duration, Instant},
};

use netwatch_core::{
    fmt_bytes, fmt_speed, fmt_time, row_color, App, Conn, COL_COUNT, COL_LABELS, POLL_INTERVAL,
};

// -- Theme colors -------------------------------------------------------------

const COLOR_SORT_ACTIVE: Color = Color::Rgb(255, 105, 180);
const COLOR_HDR_BG: Color = Color::Rgb(40, 40, 40);

// -- Row Styling --------------------------------------------------------------

fn row_style(c: &Conn) -> Style {
    match row_color(c) {
        "blue" => Style::default().fg(Color::Blue),
        "red" => Style::default().fg(Color::Red),
        "yellow" => Style::default().fg(Color::Yellow),
        _ => Style::default().fg(Color::White),
    }
}

// -- UI Drawing ---------------------------------------------------------------

fn draw(f: &mut Frame, app: &App, table_state: &mut TableState) {
    let area = f.area();
    let sorted = app.sorted_conns();
    let count = sorted.len();

    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(5),
        Constraint::Length(1),
    ])
    .split(area);

    // -- Title Bar --
    let count_str = format!(" {} connections ", count);
    let title = Line::from(vec![
        Span::styled(
            " NETWATCH ",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ),
        Span::styled(&count_str, Style::default().fg(Color::Yellow)),
    ]);
    f.render_widget(title, chunks[0]);

    // -- Column Headers --
    let base_hdr = Style::default()
        .add_modifier(Modifier::BOLD)
        .fg(Color::White)
        .bg(COLOR_HDR_BG);
    let active_hdr = Style::default()
        .add_modifier(Modifier::BOLD)
        .fg(COLOR_SORT_ACTIVE)
        .bg(COLOR_HDR_BG);

    let header = Row::new(
        COL_LABELS.iter().enumerate().map(|(i, label)| {
            let style = if i == app.sort_col { active_hdr } else { base_hdr };
            Cell::from(Line::styled(*label, style))
        }).collect::<Vec<_>>()
    );

    // -- Connection Rows --
    let rows: Vec<Row> = sorted
        .iter()
        .map(|c| {
            Row::new([
                Cell::from(c.remote.clone()),
                Cell::from(c.isp.clone()),
                Cell::from(fmt_speed(c.speed_down)),
                Cell::from(fmt_speed(c.speed_up)),
                Cell::from(fmt_bytes(c.bytes_sent)),
                Cell::from(fmt_bytes(c.bytes_recv)),
                Cell::from(fmt_time(c.first_seen)),
            ])
            .style(row_style(c))
        })
        .collect();

    let widths = [
        Constraint::Min(16),
        Constraint::Min(14),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(7),
        Constraint::Length(7),
        Constraint::Length(9),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .block(Block::default());

    f.render_stateful_widget(table, chunks[1], table_state);

    // -- Footer --
    let footer = Line::from(Span::styled(
        " q:Quit  Tab:Sort  j/k/↑/↓:Scroll  PgUp/PgDn ",
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    ));
    f.render_widget(footer, chunks[2]);
}

// -- Entry Point --------------------------------------------------------------

fn main() -> io::Result<()> {
    stdout().execute(EnterAlternateScreen)?;
    terminal::enable_raw_mode()?;

    let backend = ratatui::backend::CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;
    let mut app = App::new();
    let mut table_state = TableState::default();
    let mut last_poll = Instant::now() - Duration::from_secs(10);

    loop {
        if last_poll.elapsed() >= POLL_INTERVAL {
            app.poll();
            last_poll = Instant::now();
        }

        terminal.draw(|f| draw(f, &app, &mut table_state))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => break,
                    KeyCode::Tab => app.sort_col = (app.sort_col + 1) % COL_COUNT,
                    KeyCode::Char('j') | KeyCode::Down => table_state.scroll_down_by(1),
                    KeyCode::Char('k') | KeyCode::Up => table_state.scroll_up_by(1),
                    KeyCode::PageDown => table_state.scroll_down_by(10),
                    KeyCode::PageUp => table_state.scroll_up_by(10),
                    _ => {}
                }
            }
        }
    }

    terminal::disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}

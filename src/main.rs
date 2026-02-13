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
    collections::{HashMap, HashSet},
    io::{self, stdout},
    process::Command,
    time::{Duration, Instant, SystemTime},
};

const POLL_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone)]
struct Conn {
    local: String,
    remote: String,
    state: String,
    bytes_sent: u64,
    bytes_recv: u64,
    speed_up: f64,
    speed_down: f64,
    first_seen: SystemTime,
}

struct App {
    conns: HashMap<String, Conn>,
    sort_col: usize,
    table_state: TableState,
}

const SORT_LABELS: &[&str] = &["DOWN", "UP", "TIME", "REMOTE"];

impl App {
    fn new() -> Self {
        Self {
            conns: HashMap::new(),
            sort_col: 0,
            table_state: TableState::default(),
        }
    }

    fn poll(&mut self) {
        let Ok(output) = Command::new("ss").args(["-tinH"]).output() else {
            return;
        };
        let text = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = text.lines().collect();
        let mut seen = HashSet::new();
        let mut i = 0;

        while i < lines.len() {
            let parts: Vec<&str> = lines[i].split_whitespace().collect();
            if parts.len() < 5 {
                i += 1;
                continue;
            }
            let state = parts[0];
            if !matches!(
                state,
                "ESTAB" | "SYN-SENT" | "SYN-RECV" | "CLOSE-WAIT"
                    | "TIME-WAIT" | "FIN-WAIT1" | "FIN-WAIT2" | "LAST-ACK"
            ) {
                i += 1;
                continue;
            }
            let local = parts[3].to_string();
            let remote = parts[4].to_string();

            let mut info = String::new();
            i += 1;
            while i < lines.len() && lines[i].starts_with(['\t', ' ']) {
                info.push_str(lines[i]);
                info.push(' ');
                i += 1;
            }

            let bs = extract_field(&info, "bytes_sent:");
            let br = extract_field(&info, "bytes_received:");
            let key = format!("{}->{}", local, remote);
            seen.insert(key.clone());
            let dt = POLL_INTERVAL.as_secs_f64();

            if let Some(c) = self.conns.get_mut(&key) {
                let ds = bs.saturating_sub(c.bytes_sent);
                let dr = br.saturating_sub(c.bytes_recv);
                c.speed_up = if ds > 0 { ds as f64 / dt } else { c.speed_up * 0.5 };
                c.speed_down = if dr > 0 { dr as f64 / dt } else { c.speed_down * 0.5 };
                c.bytes_sent = bs;
                c.bytes_recv = br;
                c.state = state.to_string();
            } else {
                self.conns.insert(key, Conn {
                    local,
                    remote,
                    state: state.to_string(),
                    bytes_sent: bs,
                    bytes_recv: br,
                    speed_up: 0.0,
                    speed_down: 0.0,
                    first_seen: SystemTime::now(),
                });
            }
        }
        self.conns.retain(|k, _| seen.contains(k));
    }

    fn sorted_conns(&self) -> Vec<Conn> {
        let mut v: Vec<Conn> = self.conns.values().cloned().collect();
        match self.sort_col {
            0 => v.sort_by(|a, b| b.speed_down.partial_cmp(&a.speed_down).unwrap()),
            1 => v.sort_by(|a, b| b.speed_up.partial_cmp(&a.speed_up).unwrap()),
            2 => v.sort_by(|a, b| b.first_seen.cmp(&a.first_seen)),
            3 => v.sort_by(|a, b| a.remote.cmp(&b.remote)),
            _ => {}
        }
        v
    }
}

fn extract_field(s: &str, field: &str) -> u64 {
    s.find(field)
        .and_then(|pos| {
            let rest = &s[pos + field.len()..];
            let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            num.parse().ok()
        })
        .unwrap_or(0)
}

fn fmt_speed(bps: f64) -> String {
    if bps < 1.0 {
        "  0  B/s".into()
    } else if bps < 1024.0 {
        format!("{:>4.0}  B/s", bps)
    } else if bps < 1_048_576.0 {
        format!("{:>4.1} KB/s", bps / 1024.0)
    } else if bps < 1_073_741_824.0 {
        format!("{:>4.1} MB/s", bps / 1_048_576.0)
    } else {
        format!("{:>4.1} GB/s", bps / 1_073_741_824.0)
    }
}

fn fmt_bytes(b: u64) -> String {
    if b < 1024 {
        format!("{}B", b)
    } else if b < 1_048_576 {
        format!("{:.1}K", b as f64 / 1024.0)
    } else if b < 1_073_741_824 {
        format!("{:.1}M", b as f64 / 1_048_576.0)
    } else {
        format!("{:.1}G", b as f64 / 1_073_741_824.0)
    }
}

fn fmt_time(t: SystemTime) -> String {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    #[repr(C)]
    struct Tm {
        tm_sec: i32,
        tm_min: i32,
        tm_hour: i32,
        _rest: [i32; 6],
        _gmtoff: i64,
        _zone: *const i8,
    }
    unsafe extern "C" {
        fn localtime(t: *const i64) -> *const Tm;
    }
    unsafe {
        let tm = localtime(&secs);
        if tm.is_null() {
            "??:??:??".into()
        } else {
            format!("{:02}:{:02}:{:02}", (*tm).tm_hour, (*tm).tm_min, (*tm).tm_sec)
        }
    }
}

fn row_style(c: &Conn) -> Style {
    if c.state != "ESTAB" {
        Style::default().fg(Color::Blue)
    } else if c.speed_down > 1_048_576.0 || c.speed_up > 1_048_576.0 {
        Style::default().fg(Color::Red)
    } else if c.speed_down > 1024.0 || c.speed_up > 1024.0 {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::White)
    }
}

fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let sorted = app.sorted_conns();
    let count = sorted.len();

    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(5),
        Constraint::Length(1),
    ])
    .split(area);

    // Title bar
    let sort_str = format!(" Sort: {} (Tab) ", SORT_LABELS[app.sort_col]);
    let count_str = format!(" {} connections ", count);
    let pad_len = (area.width as usize)
        .saturating_sub(10 + count_str.len() + sort_str.len());
    let title = Line::from(vec![
        Span::styled(
            " NETWATCH ",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ),
        Span::styled(&count_str, Style::default().fg(Color::Yellow)),
        Span::raw(" ".repeat(pad_len)),
        Span::styled(&sort_str, Style::default().fg(Color::Green)),
    ]);
    f.render_widget(title, chunks[0]);

    // Table
    let header = Row::new([
        "STATE", "LOCAL", "REMOTE", "DOWN", "UP", "SENT", "RECV", "CONNECTED",
    ])
    .style(
        Style::default()
            .add_modifier(Modifier::BOLD)
            .fg(Color::Black)
            .bg(Color::White),
    );

    let rows: Vec<Row> = sorted
        .iter()
        .map(|c| {
            Row::new([
                Cell::from(c.state.clone()),
                Cell::from(c.local.clone()),
                Cell::from(c.remote.clone()),
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
        Constraint::Length(11),
        Constraint::Min(16),
        Constraint::Min(16),
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

    f.render_stateful_widget(table, chunks[1], &mut app.table_state);

    // Footer
    let footer = Line::from(Span::styled(
        " q:Quit  Tab:Sort  j/k/↑/↓:Scroll  PgUp/PgDn ",
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    ));
    f.render_widget(footer, chunks[2]);
}

fn main() -> io::Result<()> {
    stdout().execute(EnterAlternateScreen)?;
    terminal::enable_raw_mode()?;

    let backend = ratatui::backend::CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;
    let mut app = App::new();
    let mut last_poll = Instant::now() - Duration::from_secs(10);

    loop {
        if last_poll.elapsed() >= POLL_INTERVAL {
            app.poll();
            last_poll = Instant::now();
        }

        terminal.draw(|f| draw(f, &mut app))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => break,
                    KeyCode::Tab => app.sort_col = (app.sort_col + 1) % 4,
                    KeyCode::Char('j') | KeyCode::Down => app.table_state.scroll_down_by(1),
                    KeyCode::Char('k') | KeyCode::Up => app.table_state.scroll_up_by(1),
                    KeyCode::PageDown => app.table_state.scroll_down_by(10),
                    KeyCode::PageUp => app.table_state.scroll_up_by(10),
                    _ => {}
                }
            }
        }
    }

    terminal::disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}

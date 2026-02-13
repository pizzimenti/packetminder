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
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime},
};

const POLL_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone)]
struct Conn {
    remote: String,
    isp: String,
    state: String,
    bytes_sent: u64,
    bytes_recv: u64,
    speed_up: f64,
    speed_down: f64,
    first_seen: SystemTime,
}

struct App {
    conns: HashMap<String, Conn>,
    isp_cache: Arc<Mutex<HashMap<String, String>>>,
    pending_lookups: HashSet<String>,
    sort_col: usize,
    sort_ascending: bool,
    table_state: TableState,
}

const SORT_LABELS: &[&str] = &["RECV", "DOWN", "UP", "TIME", "REMOTE"];

impl App {
    fn new() -> Self {
        Self {
            conns: HashMap::new(),
            isp_cache: Arc::new(Mutex::new(HashMap::new())),
            pending_lookups: HashSet::new(),
            sort_col: 0,
            sort_ascending: false,
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
            let local = parts[3];
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
                self.spawn_isp_lookup(&remote);
                self.conns.insert(key, Conn {
                    remote,
                    isp: "...".into(),
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

        // Update ISP fields from cache
        let cache = self.isp_cache.lock().unwrap();
        for conn in self.conns.values_mut() {
            if conn.isp == "..." {
                let ip = conn.remote.rsplit_once(':').map(|(ip, _)| ip).unwrap_or(&conn.remote);
                if let Some(isp) = cache.get(ip) {
                    conn.isp = isp.clone();
                }
            }
        }
    }

    fn spawn_isp_lookup(&mut self, remote: &str) {
        let ip = remote.rsplit_once(':').map(|(ip, _)| ip).unwrap_or(remote).to_string();
        if self.pending_lookups.contains(&ip) {
            return;
        }
        self.pending_lookups.insert(ip.clone());
        let cache = Arc::clone(&self.isp_cache);
        thread::spawn(move || {
            let isp = run_whois(&ip);
            cache.lock().unwrap().insert(ip, isp);
        });
    }

    fn sorted_conns(&self) -> Vec<Conn> {
        let mut v: Vec<Conn> = self.conns.values().cloned().collect();
        match self.sort_col {
            0 => v.sort_by(|a, b| b.bytes_recv.cmp(&a.bytes_recv)),
            1 => v.sort_by(|a, b| b.speed_down.partial_cmp(&a.speed_down).unwrap()),
            2 => v.sort_by(|a, b| b.speed_up.partial_cmp(&a.speed_up).unwrap()),
            3 => v.sort_by(|a, b| b.first_seen.cmp(&a.first_seen)),
            4 => v.sort_by(|a, b| a.remote.cmp(&b.remote)),
            _ => {}
        }
        if self.sort_ascending {
            v.reverse();
        }
        v
    }
}

fn run_whois(ip: &str) -> String {
    let output = Command::new("whois").arg(ip).output();
    let output = match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => return "?".into(),
    };
    // Try common whois fields for org/ISP name
    for prefix in ["OrgName:", "org-name:", "netname:", "descr:", "Organization:"] {
        for line in output.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix(prefix) {
                let name = rest.trim();
                if !name.is_empty() {
                    return name.to_string();
                }
            }
        }
    }
    "?".into()
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
    let dir = if app.sort_ascending { "ASC" } else { "DESC" };
    let sort_str = format!(" {} {} (Tab/s) ", SORT_LABELS[app.sort_col], dir);
    let sort_color = if app.sort_ascending { Color::Yellow } else { Color::Blue };
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
        Span::styled(&sort_str, Style::default().fg(sort_color)),
    ]);
    f.render_widget(title, chunks[0]);

    // Table
    let base_hdr = Style::default().add_modifier(Modifier::BOLD).fg(Color::Black).bg(Color::White);
    // Column-to-sort-index: REMOTE_IP=4, ISP=none, DOWN=1, UP=2, SENT=none, RECV=0, CONNECTED=3
    let col_sort: [Option<usize>; 7] = [Some(4), None, Some(1), Some(2), None, Some(0), Some(3)];
    let header_labels = ["REMOTE_IP", "ISP", "DOWN", "UP", "SENT", "RECV", "CONNECTED"];
    let header = Row::new(
        header_labels.iter().enumerate().map(|(i, label)| {
            if col_sort[i] == Some(app.sort_col) {
                Cell::from(Line::from(Span::styled(
                    *label,
                    Style::default().add_modifier(Modifier::BOLD).fg(sort_color),
                )))
            } else {
                Cell::from(*label)
            }
        }).collect::<Vec<_>>()
    ).style(base_hdr);

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

    f.render_stateful_widget(table, chunks[1], &mut app.table_state);

    // Footer
    let footer = Line::from(Span::styled(
        " q:Quit  Tab:Sort  s:Asc/Desc  j/k/↑/↓:Scroll  PgUp/PgDn ",
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
                    KeyCode::Tab => app.sort_col = (app.sort_col + 1) % 5,
                    KeyCode::Char('s') => app.sort_ascending = !app.sort_ascending,
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

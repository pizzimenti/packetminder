// =============================================================================
// netwatch - A terminal UI for monitoring active TCP connections in real time.
//
// Displays remote IP, ISP (via background whois), upload/download speed,
// total bytes transferred, and the time each connection was first seen.
//
// Built with ratatui (TUI framework) and crossterm (terminal backend).
// Connection data comes from `ss -tinH` which exposes per-socket byte counters.
// =============================================================================

// -- Imports ------------------------------------------------------------------

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

// -- Constants ----------------------------------------------------------------

/// How often we poll `ss` for updated connection data (in seconds).
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Total number of table columns.
const COL_COUNT: usize = 7;

/// Column header labels, in display order (left to right).
/// Tab cycles through these for sorting.
const COL_LABELS: &[&str] = &["REMOTE_IP", "ISP", "DOWN", "UP", "SENT", "RECV", "CONNECTED"];

/// Which column to sort by on startup (5 = RECV, descending).
const DEFAULT_SORT_COL: usize = 5;

// -- Theme colors -------------------------------------------------------------

/// Hot pink for the currently-sorted column header.
const COLOR_SORT_ACTIVE: Color = Color::Rgb(255, 105, 180);

/// Dark grey background for column headers (slightly lighter than pure black).
const COLOR_HDR_BG: Color = Color::Rgb(40, 40, 40);

// -- Data Structures ----------------------------------------------------------

/// Represents a single tracked TCP connection.
#[derive(Clone)]
struct Conn {
    /// Remote address as "ip:port" (e.g. "142.250.69.170:443").
    remote: String,

    /// ISP/org name from whois lookup. Starts as "..." until the background
    /// lookup completes, then becomes the org name or "?" if lookup failed.
    isp: String,

    /// TCP state (ESTAB, CLOSE-WAIT, etc.). Used for color-coding rows.
    state: String,

    /// Cumulative bytes sent on this connection (from ss bytes_sent field).
    bytes_sent: u64,

    /// Cumulative bytes received on this connection (from ss bytes_received field).
    bytes_recv: u64,

    /// Current upload speed in bytes/sec, computed as delta between polls.
    /// Decays by 0.5x each poll if no new data is sent (smooths to zero).
    speed_up: f64,

    /// Current download speed in bytes/sec, computed as delta between polls.
    /// Decays by 0.5x each poll if no new data is received.
    speed_down: f64,

    /// When this connection was first observed by netwatch (wall clock time).
    first_seen: SystemTime,
}

/// Application state: holds all connections, the ISP lookup cache, and UI state.
struct App {
    /// Active connections, keyed by "local_addr->remote_addr" for uniqueness.
    conns: HashMap<String, Conn>,

    /// Shared cache of completed whois lookups: IP string -> ISP/org name.
    /// Written to by background threads, read by the main poll loop.
    isp_cache: Arc<Mutex<HashMap<String, String>>>,

    /// Set of IPs we've already spawned a whois thread for, to avoid duplicates.
    pending_lookups: HashSet<String>,

    /// Currently selected sort column index (0-6, maps to COL_LABELS).
    sort_col: usize,

    /// Ratatui's table widget state (tracks scroll position and selection).
    table_state: TableState,
}

// -- App Implementation -------------------------------------------------------

impl App {
    /// Create a new App with default sort on RECV column.
    fn new() -> Self {
        Self {
            conns: HashMap::new(),
            isp_cache: Arc::new(Mutex::new(HashMap::new())),
            pending_lookups: HashSet::new(),
            sort_col: DEFAULT_SORT_COL,
            table_state: TableState::default(),
        }
    }

    /// Poll `ss -tinH` for current TCP connections and update state.
    ///
    /// The `ss` command with flags:
    ///   -t  TCP sockets only
    ///   -i  Show internal TCP info (includes bytes_sent, bytes_received)
    ///   -n  Numeric output (don't resolve hostnames — faster)
    ///   -H  No header line
    ///
    /// Output format (two lines per connection):
    ///   ESTAB  0  0  192.168.1.5:43210  142.250.69.170:443
    ///        cubic wscale:7,7 rto:204 ... bytes_sent:1234 bytes_received:5678 ...
    fn poll(&mut self) {
        let Ok(output) = Command::new("ss").args(["-tinH"]).output() else {
            return;
        };
        let text = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = text.lines().collect();

        // Track which connections we see this poll cycle.
        // Any connection NOT seen will be removed (it closed).
        let mut seen = HashSet::new();
        let mut i = 0;

        while i < lines.len() {
            // -- Parse the connection line --
            // Format: STATE  RECV-Q  SEND-Q  LOCAL_ADDR:PORT  REMOTE_ADDR:PORT
            let parts: Vec<&str> = lines[i].split_whitespace().collect();
            if parts.len() < 5 {
                i += 1;
                continue;
            }

            // Only process recognized TCP states
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

            // -- Collect indented info lines that follow --
            // These contain TCP internal stats like bytes_sent, bytes_received, rtt, etc.
            let mut info = String::new();
            i += 1;
            while i < lines.len() && lines[i].starts_with(['\t', ' ']) {
                info.push_str(lines[i]);
                info.push(' ');
                i += 1;
            }

            // Extract cumulative byte counters from the info line
            let bytes_sent = extract_field(&info, "bytes_sent:");
            let bytes_recv = extract_field(&info, "bytes_received:");

            // Unique key: "local_addr->remote_addr" identifies this specific connection
            let key = format!("{}->{}", local, remote);
            seen.insert(key.clone());

            // Time between polls, used to compute speed = delta_bytes / delta_time
            let dt = POLL_INTERVAL.as_secs_f64();

            if let Some(c) = self.conns.get_mut(&key) {
                // -- Existing connection: update speed and counters --
                let delta_sent = bytes_sent.saturating_sub(c.bytes_sent);
                let delta_recv = bytes_recv.saturating_sub(c.bytes_recv);

                // If new data transferred, compute speed. Otherwise decay toward zero
                // (multiply by 0.5 each poll) so the display smoothly drops to 0.
                c.speed_up = if delta_sent > 0 {
                    delta_sent as f64 / dt
                } else {
                    c.speed_up * 0.5
                };
                c.speed_down = if delta_recv > 0 {
                    delta_recv as f64 / dt
                } else {
                    c.speed_down * 0.5
                };

                c.bytes_sent = bytes_sent;
                c.bytes_recv = bytes_recv;
                c.state = state.to_string();
            } else {
                // -- New connection: insert and kick off ISP lookup --
                self.spawn_isp_lookup(&remote);
                self.conns.insert(key, Conn {
                    remote,
                    isp: "...".into(), // placeholder until whois completes
                    state: state.to_string(),
                    bytes_sent,
                    bytes_recv,
                    speed_up: 0.0,
                    speed_down: 0.0,
                    first_seen: SystemTime::now(),
                });
            }
        }

        // Remove connections that weren't seen this poll (they've closed)
        self.conns.retain(|k, _| seen.contains(k));

        // Check if any background whois lookups have completed and
        // update the ISP field for connections still showing "..."
        let cache = self.isp_cache.lock().unwrap();
        for conn in self.conns.values_mut() {
            if conn.isp == "..." {
                // Strip the port to get just the IP for cache lookup
                let ip = conn.remote.rsplit_once(':').map(|(ip, _)| ip).unwrap_or(&conn.remote);
                if let Some(isp) = cache.get(ip) {
                    conn.isp = isp.clone();
                }
            }
        }
    }

    /// Spawn a background thread to run `whois` on the given remote address.
    /// Results are written to the shared isp_cache. Each IP is only looked up once.
    fn spawn_isp_lookup(&mut self, remote: &str) {
        // Extract just the IP (strip the :port suffix)
        let ip = remote.rsplit_once(':').map(|(ip, _)| ip).unwrap_or(remote).to_string();

        // Skip if we've already started a lookup for this IP
        if self.pending_lookups.contains(&ip) {
            return;
        }
        self.pending_lookups.insert(ip.clone());

        // Clone the Arc so the thread can write to the shared cache
        let cache = Arc::clone(&self.isp_cache);
        thread::spawn(move || {
            let isp = run_whois(&ip);
            cache.lock().unwrap().insert(ip, isp);
        });
    }

    /// Return all connections sorted by the currently selected column.
    /// Numeric columns sort descending (biggest first).
    /// String columns sort ascending (alphabetical).
    fn sorted_conns(&self) -> Vec<Conn> {
        let mut v: Vec<Conn> = self.conns.values().cloned().collect();
        match self.sort_col {
            0 => v.sort_by(|a, b| parse_ip_sort_key(&a.remote).cmp(&parse_ip_sort_key(&b.remote))),
            1 => v.sort_by(|a, b| a.isp.to_lowercase().cmp(&b.isp.to_lowercase())),
            2 => v.sort_by(|a, b| b.speed_down.partial_cmp(&a.speed_down).unwrap()),
            3 => v.sort_by(|a, b| b.speed_up.partial_cmp(&a.speed_up).unwrap()),
            4 => v.sort_by(|a, b| b.bytes_sent.cmp(&a.bytes_sent)),
            5 => v.sort_by(|a, b| b.bytes_recv.cmp(&a.bytes_recv)),
            6 => v.sort_by(|a, b| a.first_seen.cmp(&b.first_seen)),
            _ => {}
        }
        v
    }
}

// -- Whois Lookup -------------------------------------------------------------

/// Run `whois <ip>` and extract the ISP/organization name from the output.
///
/// Tries several common whois output fields in priority order:
///   OrgName:      (ARIN)
///   org-name:     (RIPE)
///   netname:      (RIPE/APNIC)
///   descr:        (APNIC/LACNIC)
///   Organization: (some registrars)
///
/// Returns "?" if whois fails or no org name is found.
fn run_whois(ip: &str) -> String {
    let output = Command::new("whois").arg(ip).output();
    let output = match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => return "?".into(),
    };

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

// -- Parsing Helpers ----------------------------------------------------------

/// Convert an "ip:port" string into a u32 for numeric IP sorting.
/// Packs the four IPv4 octets into a single 32-bit integer.
/// e.g. "192.168.1.1:443" -> 0xC0A80101
fn parse_ip_sort_key(remote: &str) -> u32 {
    let ip = remote.rsplit_once(':').map(|(ip, _)| ip).unwrap_or(remote);
    let parts: Vec<u32> = ip.split('.').filter_map(|s| s.parse().ok()).collect();
    if parts.len() == 4 {
        (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    } else {
        0
    }
}

/// Extract a numeric value from a "key:value" pair in the ss info string.
/// e.g. extract_field("... bytes_sent:1234 ...", "bytes_sent:") -> 1234
fn extract_field(s: &str, field: &str) -> u64 {
    s.find(field)
        .and_then(|pos| {
            let rest = &s[pos + field.len()..];
            let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            num.parse().ok()
        })
        .unwrap_or(0)
}

// -- Formatting Helpers -------------------------------------------------------

/// Format bytes-per-second into a human-readable speed string.
/// Automatically scales to B/s, KB/s, MB/s, or GB/s.
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

/// Format a byte count into a compact human-readable string.
/// e.g. 1536 -> "1.5K", 2621440 -> "2.5M"
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

/// Format a SystemTime as "HH:MM:SS" in local time.
///
/// Uses C's localtime() via FFI because Rust's standard library doesn't
/// provide local time formatting without pulling in a crate like chrono.
fn fmt_time(t: SystemTime) -> String {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Minimal C struct layout for the fields we need from localtime()
    #[repr(C)]
    struct Tm {
        tm_sec: i32,
        tm_min: i32,
        tm_hour: i32,
        _rest: [i32; 6],   // tm_mday, tm_mon, tm_year, tm_wday, tm_yday, tm_isdst
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

// -- Row Styling --------------------------------------------------------------

/// Choose a color for a connection row based on its state and speed.
///   - Blue:   non-established connections (closing, waiting, etc.)
///   - Red:    high speed (> 1 MB/s upload or download)
///   - Yellow: moderate speed (> 1 KB/s)
///   - White:  idle or low speed
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

// -- UI Drawing ---------------------------------------------------------------

/// Render the entire TUI frame: title bar, connection table, and footer.
fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let sorted = app.sorted_conns();
    let count = sorted.len();

    // Layout: title (1 line) + table (fills remaining space) + footer (1 line)
    let chunks = Layout::vertical([
        Constraint::Length(1),  // title bar
        Constraint::Min(5),    // connection table
        Constraint::Length(1),  // footer keybindings
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
    // Base style: bold white text on dark grey background.
    // Active sort column: hot pink text to highlight which column is sorted.
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

    // Column widths: flexible for REMOTE_IP and ISP, fixed for the rest
    let widths = [
        Constraint::Min(16),   // REMOTE_IP  — stretches to fill
        Constraint::Min(14),   // ISP        — stretches to fill
        Constraint::Length(10), // DOWN       — "9999 KB/s" fits in 10
        Constraint::Length(10), // UP
        Constraint::Length(7),  // SENT       — "999.9M" fits in 7
        Constraint::Length(7),  // RECV
        Constraint::Length(9),  // CONNECTED  — "HH:MM:SS" = 8 + padding
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .block(Block::default());

    f.render_stateful_widget(table, chunks[1], &mut app.table_state);

    // -- Footer: keybinding hints --
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
    // Enter alternate screen buffer (preserves the user's terminal on exit)
    stdout().execute(EnterAlternateScreen)?;

    // Enable raw mode: no line buffering, no echo, direct key input
    terminal::enable_raw_mode()?;

    let backend = ratatui::backend::CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;
    let mut app = App::new();

    // Force an immediate first poll by setting last_poll far in the past
    let mut last_poll = Instant::now() - Duration::from_secs(10);

    loop {
        // -- Poll for new connection data every POLL_INTERVAL --
        if last_poll.elapsed() >= POLL_INTERVAL {
            app.poll();
            last_poll = Instant::now();
        }

        // -- Redraw the UI --
        terminal.draw(|f| draw(f, &mut app))?;

        // -- Handle keyboard input (non-blocking, 100ms timeout) --
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                // Only respond to key press events (ignore release/repeat)
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => break,
                    KeyCode::Tab => app.sort_col = (app.sort_col + 1) % COL_COUNT,
                    KeyCode::Char('j') | KeyCode::Down => app.table_state.scroll_down_by(1),
                    KeyCode::Char('k') | KeyCode::Up => app.table_state.scroll_up_by(1),
                    KeyCode::PageDown => app.table_state.scroll_down_by(10),
                    KeyCode::PageUp => app.table_state.scroll_up_by(10),
                    _ => {}
                }
            }
        }
    }

    // Restore the terminal to its original state
    terminal::disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}

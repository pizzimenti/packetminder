// =============================================================================
// netwatch-core — Business logic for monitoring active TCP connections.
//
// Provides connection polling (via `ss`), whois ISP lookups, speed tracking,
// and formatting helpers. Used by both the TUI and Qt GUI frontends.
// =============================================================================

use pyo3::prelude::*;
use std::{
    collections::{HashMap, HashSet},
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime},
};

// -- Constants ----------------------------------------------------------------

/// How often we poll `ss` for updated connection data (in seconds).
pub const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Total number of table columns.
pub const COL_COUNT: usize = 7;

/// Column header labels, in display order (left to right).
pub const COL_LABELS: &[&str] = &["REMOTE_IP", "ISP", "DOWN", "UP", "SENT", "RECV", "CONNECTED"];

/// Which column to sort by on startup (5 = RECV, descending).
pub const DEFAULT_SORT_COL: usize = 5;

// -- Data Structures ----------------------------------------------------------

/// Represents a single tracked TCP connection.
#[derive(Clone)]
pub struct Conn {
    pub remote: String,
    pub isp: String,
    pub state: String,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub speed_up: f64,
    pub speed_down: f64,
    pub first_seen: SystemTime,
}

/// Application state: holds all connections, the ISP lookup cache, and sort state.
pub struct App {
    pub conns: HashMap<String, Conn>,
    pub isp_cache: Arc<Mutex<HashMap<String, String>>>,
    pub pending_lookups: HashSet<String>,
    pub sort_col: usize,
}

// -- App Implementation -------------------------------------------------------

impl App {
    pub fn new() -> Self {
        Self {
            conns: HashMap::new(),
            isp_cache: Arc::new(Mutex::new(HashMap::new())),
            pending_lookups: HashSet::new(),
            sort_col: DEFAULT_SORT_COL,
        }
    }

    /// Poll `ss -tinH` for current TCP connections and update state.
    pub fn poll(&mut self) {
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

            let bytes_sent = extract_field(&info, "bytes_sent:");
            let bytes_recv = extract_field(&info, "bytes_received:");

            let key = format!("{}->{}", local, remote);
            seen.insert(key.clone());

            let dt = POLL_INTERVAL.as_secs_f64();

            if let Some(c) = self.conns.get_mut(&key) {
                let delta_sent = bytes_sent.saturating_sub(c.bytes_sent);
                let delta_recv = bytes_recv.saturating_sub(c.bytes_recv);

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
                self.spawn_isp_lookup(&remote);
                self.conns.insert(key, Conn {
                    remote,
                    isp: "...".into(),
                    state: state.to_string(),
                    bytes_sent,
                    bytes_recv,
                    speed_up: 0.0,
                    speed_down: 0.0,
                    first_seen: SystemTime::now(),
                });
            }
        }

        self.conns.retain(|k, _| seen.contains(k));

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

    /// Spawn a background thread to run `whois` on the given remote address.
    pub fn spawn_isp_lookup(&mut self, remote: &str) {
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

    /// Return all connections sorted by the currently selected column.
    pub fn sorted_conns(&self) -> Vec<Conn> {
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
pub fn run_whois(ip: &str) -> String {
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
pub fn parse_ip_sort_key(remote: &str) -> u32 {
    let ip = remote.rsplit_once(':').map(|(ip, _)| ip).unwrap_or(remote);
    let parts: Vec<u32> = ip.split('.').filter_map(|s| s.parse().ok()).collect();
    if parts.len() == 4 {
        (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    } else {
        0
    }
}

/// Extract a numeric value from a "key:value" pair in the ss info string.
pub fn extract_field(s: &str, field: &str) -> u64 {
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
pub fn fmt_speed(bps: f64) -> String {
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
pub fn fmt_bytes(b: u64) -> String {
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
pub fn fmt_time(t: SystemTime) -> String {
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

/// Choose a row color name based on connection state and speed.
/// Returns: "blue", "red", "yellow", or "white".
pub fn row_color(c: &Conn) -> &'static str {
    if c.state != "ESTAB" {
        "blue"
    } else if c.speed_down > 1_048_576.0 || c.speed_up > 1_048_576.0 {
        "red"
    } else if c.speed_down > 1024.0 || c.speed_up > 1024.0 {
        "yellow"
    } else {
        "white"
    }
}

// =============================================================================
// PyO3 Bindings — Exposes netwatch-core to Python as a native module.
// =============================================================================

/// Python-facing connection data (read-only snapshot).
#[pyclass(from_py_object)]
#[derive(Clone)]
pub struct Connection {
    #[pyo3(get)]
    pub remote: String,
    #[pyo3(get)]
    pub isp: String,
    #[pyo3(get)]
    pub state: String,
    #[pyo3(get)]
    pub bytes_sent: u64,
    #[pyo3(get)]
    pub bytes_recv: u64,
    #[pyo3(get)]
    pub speed_up: f64,
    #[pyo3(get)]
    pub speed_down: f64,
    #[pyo3(get)]
    pub first_seen_str: String,
    #[pyo3(get)]
    pub speed_down_fmt: String,
    #[pyo3(get)]
    pub speed_up_fmt: String,
    #[pyo3(get)]
    pub bytes_sent_fmt: String,
    #[pyo3(get)]
    pub bytes_recv_fmt: String,
    #[pyo3(get)]
    pub color: String,
}

/// Python-facing wrapper around the App state.
#[pyclass]
pub struct NetwatchCore {
    app: App,
}

#[pymethods]
impl NetwatchCore {
    #[new]
    fn new() -> Self {
        Self { app: App::new() }
    }

    /// Poll for current connections and return a list of Connection objects.
    fn poll(&mut self) -> Vec<Connection> {
        self.app.poll();
        self.app
            .sorted_conns()
            .iter()
            .map(|c| Connection {
                remote: c.remote.clone(),
                isp: c.isp.clone(),
                state: c.state.clone(),
                bytes_sent: c.bytes_sent,
                bytes_recv: c.bytes_recv,
                speed_up: c.speed_up,
                speed_down: c.speed_down,
                first_seen_str: fmt_time(c.first_seen),
                speed_down_fmt: fmt_speed(c.speed_down),
                speed_up_fmt: fmt_speed(c.speed_up),
                bytes_sent_fmt: fmt_bytes(c.bytes_sent),
                bytes_recv_fmt: fmt_bytes(c.bytes_recv),
                color: row_color(c).to_string(),
            })
            .collect()
    }

    /// Get the current sort column index.
    fn sort_col(&self) -> usize {
        self.app.sort_col
    }

    /// Set the sort column index.
    fn set_sort_col(&mut self, col: usize) {
        if col < COL_COUNT {
            self.app.sort_col = col;
        }
    }

    /// Cycle to the next sort column.
    fn next_sort_col(&mut self) {
        self.app.sort_col = (self.app.sort_col + 1) % COL_COUNT;
    }

    /// Get column labels.
    fn col_labels(&self) -> Vec<String> {
        COL_LABELS.iter().map(|s| s.to_string()).collect()
    }
}

/// Python module definition.
#[pymodule]
fn netwatch_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Connection>()?;
    m.add_class::<NetwatchCore>()?;
    Ok(())
}

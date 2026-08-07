// =============================================================================
// packetminder-core — Business logic for monitoring active TCP connections.
//
// Provides connection polling (via `ss`), whois ISP lookups, speed tracking,
// and formatting helpers. The TUI is a thin display layer over this.
// =============================================================================

use std::{
    collections::{HashMap, HashSet},
    io::Read as _,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime},
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
    /// Lookups currently in flight. Shared with the workers so each can clear
    /// its own entry on completion — an entry that never cleared meant an IP
    /// whose first lookup raced a disconnect could never be looked up again.
    pub pending_lookups: Arc<Mutex<HashSet<String>>>,
    pub sort_col: usize,
}

// -- App Implementation -------------------------------------------------------

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        Self {
            conns: HashMap::new(),
            isp_cache: Arc::new(Mutex::new(HashMap::new())),
            pending_lookups: Arc::new(Mutex::new(HashSet::new())),
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

        // Not unwrap: a poisoned lock here (a panicked worker) would take the
        // main loop down with it, and stale "..." cells are the better failure.
        if let Ok(cache) = self.isp_cache.lock() {
            for conn in self.conns.values_mut() {
                if conn.isp == "..." {
                    let ip =
                        conn.remote.rsplit_once(':').map(|(ip, _)| ip).unwrap_or(&conn.remote);
                    if let Some(isp) = cache.get(ip) {
                        conn.isp = isp.clone();
                    }
                }
            }
        }
    }

    /// Spawn a background thread to run `whois` on the given remote address.
    pub fn spawn_isp_lookup(&mut self, remote: &str) {
        let ip = remote.rsplit_once(':').map(|(ip, _)| ip).unwrap_or(remote).to_string();

        // The cache is checked before anything is spawned. Short-lived
        // connections to one host reappear constantly, and without this every
        // reappearance re-ran whois for an answer already in hand — failures
        // included, since "?" is cached too.
        if let Ok(cache) = self.isp_cache.lock()
            && cache.contains_key(&ip)
        {
            return;
        }

        if let Ok(mut pending) = self.pending_lookups.lock() {
            if !pending.insert(ip.clone()) {
                return; // already in flight
            }
        } else {
            return;
        }

        let cache = Arc::clone(&self.isp_cache);
        let pending = Arc::clone(&self.pending_lookups);
        thread::spawn(move || {
            let isp = run_whois(&ip);
            if let Ok(mut cache) = cache.lock() {
                cache.insert(ip.clone(), isp);
            }
            if let Ok(mut pending) = pending.lock() {
                pending.remove(&ip);
            }
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

/// How long a whois answer stays worth waiting for. whois servers hang for
/// minutes when unreachable, and an unbounded wait pinned its worker thread
/// for the duration.
const WHOIS_TIMEOUT: Duration = Duration::from_secs(10);

/// Run `whois <ip>` with a hard deadline, extracting the ISP/organization
/// name. "?" on any failure, timeout included.
///
/// The child is killed and reaped at the deadline — merely abandoning the wait
/// leaves a whois that never exits running forever, and a retried IP could
/// stack another one behind it. A separate thread drains stdout continuously,
/// so a chatty registry cannot fill the pipe, block the child, and turn a slow
/// answer into a timeout.
pub fn run_whois(ip: &str) -> String {
    let Ok(mut child) = Command::new("whois")
        .arg(ip)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return "?".into();
    };

    let (tx, rx) = std::sync::mpsc::channel();
    if let Some(mut stdout) = child.stdout.take() {
        thread::spawn(move || {
            let mut text = String::new();
            let _ = stdout.read_to_string(&mut text);
            let _ = tx.send(text);
        });
    }

    let deadline = Instant::now() + WHOIS_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return "?".into();
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(_) => return "?".into(),
        }
    }

    let Ok(output) = rx.recv_timeout(Duration::from_secs(1)) else {
        return "?".into();
    };
    parse_whois_org(&output)
}

fn parse_whois_org(output: &str) -> String {
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
    // Octets parse as u8, not a wider type: "999.0.0.1" must sort as garbage
    // (0), not shift a too-large value into the high byte — which overflowed,
    // panicking in debug builds on any malformed address `ss` ever printed.
    //
    // Every component must parse, and there must be exactly four. The earlier
    // filter_map dropped failures, so "1.2.bad.3.4" collapsed to four valid
    // octets and sorted as a real address.
    let mut octets = [0u8; 4];
    let mut count = 0;
    for part in ip.split('.') {
        let Ok(octet) = part.parse() else { return 0 };
        if count == 4 {
            return 0; // five or more components
        }
        octets[count] = octet;
        count += 1;
    }
    if count == 4 { u32::from_be_bytes(octets) } else { 0 }
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
        // The _r variant writes into a caller-owned buffer. Plain localtime()
        // returns a pointer into one process-wide static, which is fine right
        // up until a second thread calls it — and this crate already spawns
        // threads for whois lookups.
        fn localtime_r(t: *const i64, result: *mut Tm) -> *mut Tm;
    }

    let mut tm = Tm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        _rest: [0; 6],
        _gmtoff: 0,
        _zone: std::ptr::null(),
    };
    let ok = unsafe { !localtime_r(&secs, &mut tm).is_null() };
    if ok {
        format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
    } else {
        "??:??:??".into()
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

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sort_keys_order_addresses_numerically() {
        assert!(parse_ip_sort_key("10.3.59.7:443") < parse_ip_sort_key("10.3.60.1:80"));
        assert!(parse_ip_sort_key("9.255.255.255") < parse_ip_sort_key("10.0.0.0"));
        assert_eq!(parse_ip_sort_key("10.3.59.7:443"), parse_ip_sort_key("10.3.59.7"));
    }

    #[test]
    fn malformed_addresses_sort_as_zero_rather_than_panicking() {
        // An octet over 255 used to be shifted into the high byte, which
        // overflowed and panicked in debug builds.
        assert_eq!(parse_ip_sort_key("999.999.999.999"), 0);
        assert_eq!(parse_ip_sort_key("[2605:59ca::1]:443"), 0);
        assert_eq!(parse_ip_sort_key("not an address"), 0);
        assert_eq!(parse_ip_sort_key(""), 0);
        // A bad component must poison the whole address, not be skipped so the
        // remaining four sort as if they were the real thing.
        assert_eq!(parse_ip_sort_key("1.2.bad.3.4"), 0);
        assert_eq!(parse_ip_sort_key("1.2.bad.4"), 0);
        assert_eq!(parse_ip_sort_key("1.2.3.4.5"), 0);
    }

    #[test]
    fn extracts_numeric_fields_from_ss_info() {
        let info = "bbr rto:230 bytes_sent:29955 bytes_received:29619 segs_out:717";
        assert_eq!(extract_field(info, "bytes_received:"), 29619);
        assert_eq!(extract_field(info, "bytes_sent:"), 29955);
        assert_eq!(extract_field(info, "bytes_imaginary:"), 0);
    }
}


// =============================================================================
// alert — event log, desktop notifications, and source enrichment.
//
// Detectors produce an `Alert`; this module is the only thing that decides how
// it reaches a human. Every alert is appended to the log unconditionally and
// echoed to stderr (so it lands in the journal); notification is best-effort.
// =============================================================================

use std::{
    collections::HashMap,
    fmt::Write as _,
    fs::{self, OpenOptions},
    io::Write as _,
    net::Ipv4Addr,
    process::{Command, Stdio},
    sync::{Mutex, OnceLock, mpsc::channel},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::config::Config;

// -- Data Structures ----------------------------------------------------------

pub struct Alert {
    /// Machine-readable category, e.g. "asymmetric-inbound".
    pub kind: &'static str,
    /// Stable dedup key; repeat alerts with the same key replace the popup.
    pub key: String,
    pub title: String,
    pub body: String,
    /// "low" | "normal" | "critical"
    pub urgency: &'static str,
}

// -- Emitting -----------------------------------------------------------------

pub fn emit(cfg: &Config, alert: &Alert) {
    let flat = alert.body.replace('\n', " | ");
    log(cfg, &format!("{} — {} | {}", alert.kind, alert.title, flat));

    if cfg.notify {
        notify(alert);
    }
}

/// Append a timestamped line to the event log and echo it to stderr.
pub fn log(cfg: &Config, message: &str) {
    let line = format!("{} {}\n", fmt_iso_local(now_epoch()), message);
    eprint!("{line}");

    if let Some(parent) = cfg.log_path.parent()
        && let Err(e) = fs::create_dir_all(parent)
    {
        eprintln!("netwatch-alertd: cannot create {}: {e}", parent.display());
        return;
    }

    match OpenOptions::new().create(true).append(true).open(&cfg.log_path) {
        Ok(mut fh) => {
            if let Err(e) = fh.write_all(line.as_bytes()) {
                eprintln!("netwatch-alertd: cannot write log: {e}");
            }
        }
        Err(e) => eprintln!(
            "netwatch-alertd: cannot open {}: {e}",
            cfg.log_path.display()
        ),
    }
}

fn notify(alert: &Alert) {
    // The synchronous hint makes a repeat alert replace its predecessor rather
    // than stacking another popup on the pile.
    let hint = format!("string:x-canonical-private-synchronous:netwatch-{}", alert.key);
    let result = Command::new("notify-send")
        .args([
            "-a",
            "netwatch",
            "-u",
            alert.urgency,
            "-i",
            "network-wired",
            "-h",
            &hint,
            &alert.title,
            &alert.body,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    if let Err(e) = result {
        eprintln!("netwatch-alertd: notify-send failed: {e}");
    }
}

// -- Source Enrichment --------------------------------------------------------

/// How long a resolved — or unresolved — name is reused before asking again.
/// Long enough that a 10-second tick never re-runs `getent`, short enough that
/// a DHCP reassignment stops being attributed to the address's previous holder.
const NAME_TTL_SECS: i64 = 300;

type NameCache = Mutex<HashMap<String, (Option<String>, i64)>>;

fn name_cache() -> &'static NameCache {
    static CACHE: OnceLock<NameCache> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Name an address the way a human recognises it — `caldera.lan (10.3.59.7)` —
/// falling back to the bare address when nothing resolves.
///
/// The address is always kept alongside the name. A name alone is ambiguous
/// after a DHCP reshuffle, and the address is what you need to write a firewall
/// rule or start a capture.
pub fn host_label(ip: &str) -> String {
    match hostname_for(ip) {
        Some(name) => format!("{name} ({ip})"),
        None => ip.to_string(),
    }
}

/// Cached reverse lookup.
///
/// Resolution goes through `getent hosts`, so it uses whatever nsswitch is
/// configured with — which on a desktop includes mDNS and systemd-resolved's
/// cache, not just unicast PTR. That is what makes LAN peers resolvable at all,
/// since a home router rarely serves PTR records for its DHCP leases.
///
/// Negative results are cached too: a LAN without reverse records would
/// otherwise pay the full lookup timeout on every single tick.
pub fn hostname_for(ip: &str) -> Option<String> {
    let now = now_epoch();

    if let Ok(cache) = name_cache().lock()
        && let Some((name, at)) = cache.get(ip)
        && now - at < NAME_TTL_SECS
    {
        return name.clone();
    }

    let name = reverse_dns(ip);
    if let Ok(mut cache) = name_cache().lock() {
        cache.insert(ip.to_string(), (name.clone(), now));
    }
    name
}

/// Context for a source address beyond its name: which network it sits on, and
/// who operates it. The name itself is already in the alert title.
///
/// `nearby` must come from `LocalNet::is_on_link`, not from the address class.
/// Asking whois about a neighbour returns a confident, correct, and thoroughly
/// misleading answer — it names whoever owns the allocation, so a machine on
/// the same switch gets reported as an ISP on the far side of the internet.
pub fn describe_source(ip: &str, nearby: bool) -> String {
    let mut parts: Vec<String> = Vec::new();

    if nearby {
        // whois has nothing useful to say about a neighbour, but the neighbour
        // table does — a MAC identifies the device even after its lease moves.
        parts.push("LAN".to_string());
        if let Some(mac) = neighbour_mac(ip) {
            parts.push(mac);
        }
    } else {
        parts.push("internet".to_string());
        if let Some(isp) = whois_org(ip, 5) {
            parts.push(isp);
        }
    }

    parts.join(", ")
}

/// True for RFC1918, CGNAT, link-local and loopback space.
pub fn is_private(ip: &str) -> bool {
    let Ok(addr) = ip.parse::<Ipv4Addr>() else {
        // Treat IPv6 ULA/link-local as private; anything else public.
        let lower = ip.to_lowercase();
        return lower.starts_with("fd") || lower.starts_with("fe80") || lower == "::1";
    };
    let [a, b, ..] = addr.octets();
    addr.is_private()
        || addr.is_loopback()
        || addr.is_link_local()
        // 100.64.0.0/10, carrier-grade NAT — also where Tailscale lives.
        || (a == 100 && (64..128).contains(&b))
}

fn reverse_dns(ip: &str) -> Option<String> {
    let query = ip.to_string();
    with_timeout(2, move || {
        let out = Command::new("getent")
            .args(["hosts", &query])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        // Output is "<address> <canonical name> [aliases…]".
        let text = String::from_utf8_lossy(&out.stdout);
        let name = text.split_whitespace().nth(1)?;
        if name.is_empty() || name == query {
            None
        } else {
            Some(name.to_string())
        }
    })
    .flatten()
}

fn neighbour_mac(ip: &str) -> Option<String> {
    let out = Command::new("ip").args(["neigh", "show", ip]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut fields = text.split_whitespace();
    while let Some(f) = fields.next() {
        if f == "lladdr" {
            return fields.next().map(str::to_string);
        }
    }
    None
}

fn whois_org(ip: &str, timeout_secs: u64) -> Option<String> {
    let query = ip.to_string();
    with_timeout(timeout_secs, move || {
        let text = Command::new("whois")
            .arg(&query)
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())?;

        for prefix in [
            "OrgName:",
            "org-name:",
            "netname:",
            "descr:",
            "Organization:",
        ] {
            for line in text.lines() {
                if let Some(rest) = line.trim().strip_prefix(prefix) {
                    let name = rest.trim();
                    if !name.is_empty() {
                        return Some(name.to_string());
                    }
                }
            }
        }
        None
    })
    .flatten()
}

/// Run `f` on a helper thread, giving up after `secs`.
///
/// Every enrichment lookup shells out either to something that talks to the
/// network (`whois`) or to a resolver that may itself be waiting on the network
/// (`getent`). Neither may be allowed to stall the detector loop, and on this
/// host the resolver stalling is exactly the condition being investigated.
fn with_timeout<T: Send + 'static>(secs: u64, f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let (tx, rx) = channel();
    thread::spawn(move || {
        // The receiver is gone on timeout; that is expected, not an error.
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(secs)).ok()
}

// -- Local Socket Lookup ------------------------------------------------------

/// Is any local socket bound to this port? Answers "should we have been
/// receiving this at all?" without needing root.
pub fn port_in_use(proto: &str, port: u16) -> bool {
    let files: &[&str] = match proto.to_ascii_uppercase().as_str() {
        "UDP" => &["udp", "udp6"],
        "TCP" => &["tcp", "tcp6"],
        _ => return false,
    };

    for name in files {
        let Ok(text) = fs::read_to_string(format!("/proc/net/{name}")) else {
            continue;
        };
        for line in text.lines().skip(1) {
            // Column 1 is local_address as HEX_ADDR:HEX_PORT.
            let Some(local) = line.split_whitespace().nth(1) else {
                continue;
            };
            let Some((_, hex_port)) = local.rsplit_once(':') else {
                continue;
            };
            if u16::from_str_radix(hex_port, 16) == Ok(port) {
                return true;
            }
        }
    }
    false
}

// -- Formatting ---------------------------------------------------------------

/// Format bits/sec the way a human reads a speed test.
pub fn fmt_bits(bps: f64) -> String {
    if bps >= 1_000_000.0 {
        format!("{:.2} Mbps", bps / 1_000_000.0)
    } else if bps >= 1_000.0 {
        format!("{:.1} Kbps", bps / 1_000.0)
    } else {
        format!("{bps:.0} bps")
    }
}

/// Format a byte count. Binary units, because this is memory-of-the-wire, not
/// marketing.
pub fn fmt_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

pub fn fmt_duration(secs: u64) -> String {
    let mut out = String::new();
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        let _ = write!(out, "{h}h");
    }
    if m > 0 {
        let _ = write!(out, "{m}m");
    }
    if h == 0 && m == 0 {
        let _ = write!(out, "{s}s");
    }
    out
}

pub fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// -- Local Time ---------------------------------------------------------------
//
// glibc's `struct tm`, laid out by hand so we can call localtime_r without
// pulling in the libc crate. netwatch-core does the same thing for its clock
// column.

#[repr(C)]
struct Tm {
    tm_sec: i32,
    tm_min: i32,
    tm_hour: i32,
    tm_mday: i32,
    tm_mon: i32,
    tm_year: i32,
    tm_wday: i32,
    tm_yday: i32,
    tm_isdst: i32,
    tm_gmtoff: i64,
    tm_zone: *const i8,
}

unsafe extern "C" {
    fn localtime_r(time: *const i64, result: *mut Tm) -> *mut Tm;
}

/// Format an epoch timestamp as local-time ISO 8601, e.g. 2026-08-03T00:53:29.
pub fn fmt_iso_local(epoch: i64) -> String {
    let mut tm = Tm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        tm_mday: 0,
        tm_mon: 0,
        tm_year: 0,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0,
        tm_gmtoff: 0,
        tm_zone: std::ptr::null(),
    };

    let ok = unsafe { !localtime_r(&epoch, &mut tm).is_null() };
    if !ok {
        return format!("epoch:{epoch}");
    }

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

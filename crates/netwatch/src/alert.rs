// =============================================================================
// alert — event log, desktop notifications, and source enrichment.
//
// Detectors produce an `Alert`; this module is the only thing that decides how
// it reaches a human. Every alert is written to stderr unconditionally, which
// under the systemd user unit is the journal; notification is best-effort.
//
// The journal is the only log. It already timestamps, rotates and caps what it
// stores, and `journalctl --user -u netwatch` queries it, so keeping a second
// hand-rolled copy on disk bought nothing but a file that could grow forever.
// =============================================================================

use std::{
    collections::HashMap,
    fmt::Write as _,
    fs,
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
    /// Short enough for a popup. Two lines is the budget: notification daemons
    /// scroll or clip anything longer, and the clipped part is invisible.
    pub body: String,
    /// Context worth keeping but not worth interrupting for. Journal only.
    pub detail: String,
    /// "low" | "normal" | "critical"
    pub urgency: &'static str,
}

// -- Emitting -----------------------------------------------------------------

pub fn emit(cfg: &Config, alert: &Alert) {
    // The journal gets everything; the popup gets only `body`. Splitting them
    // is the whole point -- a notification that has to be scrolled has already
    // failed, but the context is still worth keeping somewhere.
    let mut line = format!(
        "{} — {} | {}",
        alert.kind,
        alert.title,
        alert.body.replace('\n', " | ")
    );
    if !alert.detail.is_empty() {
        line.push_str(" | ");
        line.push_str(&alert.detail.replace('\n', " | "));
    }
    log(&line);

    if cfg.notify {
        notify(alert);
    }
}

/// Write a timestamped line to stderr, which the user unit routes to the
/// journal.
///
/// The timestamp is redundant under systemd, which stamps every entry itself,
/// but it keeps the line self-describing when the daemon is run by hand.
pub fn log(message: &str) {
    eprint!("{} {}\n", fmt_iso_local(now_epoch()), message);
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
        eprintln!("netwatch: notify-send failed: {e}");
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

/// OUI → vendor, cached with no expiry. The IEEE assignment behind a MAC
/// prefix does not change, so unlike a DHCP name this never goes stale.
/// Negative results are cached too, so an unregistered prefix costs one lookup.
type VendorCache = Mutex<HashMap<String, Option<String>>>;

fn vendor_cache() -> &'static VendorCache {
    static CACHE: OnceLock<VendorCache> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Name a device the way its owner would recognise it — `Roku (10.3.193.195)`,
/// `caldera.lan (10.3.59.7)` — falling back to the bare address.
///
/// Prefers a hostname a person plausibly chose, and the vendor behind the MAC
/// when it is obviously machine-generated. Consumer hardware publishes mDNS
/// names like `X01000EKSRNP.local`, which identifies nothing and is worse than
/// useless in a popup you have two seconds to read. "Roku" identifies it
/// instantly, and it is the same answer whether or not mDNS resolved at all.
///
/// The address is always kept alongside the name. A name alone is ambiguous
/// after a DHCP reshuffle, and the address is what you need to write a firewall
/// rule or start a capture.
pub fn device_label(ip: &str) -> String {
    let named = hostname_for(ip);
    let short = named
        .as_deref()
        .and_then(|n| n.split('.').next())
        .filter(|n| !n.is_empty());

    if let Some(name) = short
        && !looks_machine_generated(name)
    {
        return format!("{name} ({ip})");
    }

    match vendor_for(ip) {
        Some(vendor) => format!("{vendor} ({ip})"),
        // No vendor to fall back on, so a serial beats nothing.
        None => match short {
            Some(name) => format!("{name} ({ip})"),
            None => ip.to_string(),
        },
    }
}

/// True for names no human picked: `X01000EKSRNP`, `AC233FA1B2C3`. Shouting
/// alphanumerics of identifier length, with no lowercase anywhere.
fn looks_machine_generated(label: &str) -> bool {
    label.len() >= 8
        && label.chars().any(|c| c.is_ascii_digit())
        && !label.chars().any(|c| c.is_ascii_lowercase())
}

/// Vendor behind an address's MAC, via the neighbour table and systemd's hwdb.
///
/// hwdb ships the IEEE OUI registry pre-compiled, so this stays a local lookup
/// with no network call and no new dependency — the same bargain the rest of
/// this module strikes with `getent` and `ip`.
pub fn vendor_for(ip: &str) -> Option<String> {
    let mac = neighbour_mac(ip)?;
    let oui: String = mac
        .split(':')
        .take(3)
        .flat_map(|b| b.chars())
        .collect::<String>()
        .to_uppercase();
    if oui.len() != 6 {
        return None;
    }

    if let Ok(cache) = vendor_cache().lock()
        && let Some(hit) = cache.get(&oui)
    {
        return hit.clone();
    }

    let found = hwdb_oui(&oui).map(|raw| tidy_vendor(&raw));
    if let Ok(mut cache) = vendor_cache().lock() {
        cache.insert(oui, found.clone());
    }
    found
}

fn hwdb_oui(oui: &str) -> Option<String> {
    let out = Command::new("systemd-hwdb")
        .args(["query", &format!("OUI:{oui}")])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find_map(|l| l.strip_prefix("ID_OUI_FROM_DATABASE="))
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// "Roku, Inc" → "Roku". The registry is full of legal boilerplate that costs
/// popup width and tells you nothing about which box on the shelf it is.
fn tidy_vendor(raw: &str) -> String {
    let head = raw.split(',').next().unwrap_or(raw).trim();
    let mut best = head;
    // Legal suffixes first, descriptor words second. One pass, so the order is
    // the behaviour: strip "Inc" before "Technologies" or "Amazon Technologies
    // Inc" keeps the word that carries no information.
    for suffix in [
        " Inc.",
        " Inc",
        " Ltd.",
        " Ltd",
        " LLC",
        " GmbH",
        " B.V.",
        " Co.",
        " Co",
        " Corporation",
        " Corporate",
        " Company",
        " Technologies",
        " Technology",
        " Electronics",
        " Systems",
    ] {
        if let Some(stripped) = best.strip_suffix(suffix)
            && !stripped.trim().is_empty()
        {
            best = stripped.trim_end();
        }
    }
    if best.is_empty() { raw.to_string() } else { best.to_string() }
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

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_names_are_told_apart_from_chosen_ones() {
        // The whole point: a Roku's mDNS name identifies nothing.
        assert!(looks_machine_generated("X01000EKSRNP"));
        assert!(looks_machine_generated("AC233FA1B2C3"));

        // Names a person picked, in the shapes people actually pick them.
        assert!(!looks_machine_generated("caldera"));
        assert!(!looks_machine_generated("ithilien"));
        assert!(!looks_machine_generated("Living-Room-TV"));
        assert!(!looks_machine_generated("nas2"));

        // Short and shouty is ambiguous, so it is left alone rather than
        // guessed at -- a hostname beats no hostname.
        assert!(!looks_machine_generated("NAS"));
        assert!(!looks_machine_generated("ROUTER"));
    }

    #[test]
    fn vendor_names_lose_their_legal_boilerplate() {
        assert_eq!(tidy_vendor("Roku, Inc"), "Roku");
        assert_eq!(tidy_vendor("Cisco Systems, Inc"), "Cisco");
        assert_eq!(tidy_vendor("Intel Corporate"), "Intel");
        assert_eq!(tidy_vendor("Amazon Technologies Inc"), "Amazon");
        assert_eq!(tidy_vendor("Nintendo Co., Ltd"), "Nintendo");

        // Nothing to strip, and nothing that strips down to nothing.
        assert_eq!(tidy_vendor("Google"), "Google");
        assert_eq!(tidy_vendor("Inc"), "Inc");
    }
}

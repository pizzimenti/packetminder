// =============================================================================
// alert — event log, desktop notifications, and source enrichment.
//
// Detectors produce an `Alert`; this module is the only thing that decides how
// it reaches a human. Every alert is written to stderr unconditionally, which
// under the systemd user unit is the journal; notification is best-effort.
//
// The journal is the only log. It already timestamps, rotates and caps what it
// stores, and `journalctl --user -u packetminder` queries it, so keeping a second
// hand-rolled copy on disk bought nothing but a file that could grow forever.
// =============================================================================

use std::{
    collections::HashMap,
    env,
    fmt::Write as _,
    fs,
    io::Read as _,
    net::Ipv4Addr,
    process::{Command, Stdio},
    sync::{Mutex, OnceLock, mpsc::channel},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::config::Config;

// -- Data Structures ----------------------------------------------------------

#[derive(Clone)]
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

/// How long the notify thread babysits a popup's button before killing the
/// waiter. KDE keeps critical-urgency notifications on screen until they are
/// dismissed, so an unbounded wait held a thread and a notify-send process for
/// as long as the popup sat there.
const BUTTON_WAIT_SECS: u64 = 600;

/// Returns the handle of the thread waiting on the popup, when one was
/// spawned. The daemon ignores it — it never exits, so detached is fine.
/// `--selftest` joins it, so it waits exactly as long as the popup lives
/// instead of a guessed constant.
pub fn emit(cfg: &Config, alert: &Alert) -> Option<thread::JoinHandle<()>> {
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

    if cfg.notify { notify(cfg, alert) } else { None }
}

/// Write a timestamped line to stderr, which the user unit routes to the
/// journal.
///
/// The timestamp is redundant under systemd, which stamps every entry itself,
/// but it keeps the line self-describing when the daemon is run by hand.
pub fn log(message: &str) {
    eprintln!("{} {}", fmt_iso_local(now_epoch()), message);
}

fn notify(cfg: &Config, alert: &Alert) -> Option<thread::JoinHandle<()>> {
    // The synchronous hint makes a repeat alert replace its predecessor rather
    // than stacking another popup on the pile.
    let hint = format!("string:x-canonical-private-synchronous:packetminder-{}", alert.key);
    let launch = tui_command(cfg);

    let mut args: Vec<String> = vec![
        "-a".into(),
        "packetminder".into(),
        "-u".into(),
        alert.urgency.into(),
        "-i".into(),
        "network-wired".into(),
        "-h".into(),
        hint,
    ];
    if launch.is_some() {
        args.push("-A".into());
        args.push("tui=Open packetminder".into());
    }
    args.push(alert.title.clone());
    args.push(alert.body.clone());

    // `-A` implies `--wait`: notify-send stays alive until the popup is
    // dismissed or the button is pressed, then prints the action name on
    // stdout. So it must be spawned and waited on off the detector loop, which
    // cannot stall for however long a notification sits on somebody's screen.
    let spawned = Command::new("notify-send")
        .args(&args)
        .stdout(if launch.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stderr(Stdio::null())
        .spawn();

    let mut child = match spawned {
        Ok(child) => child,
        Err(e) => {
            eprintln!("packetminder: notify-send failed: {e}");
            return None;
        }
    };

    Some(thread::spawn(move || {
        // Poll rather than block: `--wait` lives as long as the popup, and a
        // critical-urgency popup lives until somebody dismisses it. Past the
        // deadline the waiter is killed — the button goes dead, the thread and
        // process are reclaimed, and the alert itself was delivered long ago.
        let deadline = Instant::now() + Duration::from_secs(BUTTON_WAIT_SECS);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
                Ok(None) => thread::sleep(Duration::from_secs(2)),
                Err(_) => return,
            }
        }

        let Some(cmd) = launch else {
            return; // No button was offered; the wait was only to reap it.
        };
        // notify-send writes at most one action name, far below the pipe
        // buffer, so reading after exit cannot have blocked the child.
        let mut pressed = String::new();
        if let Some(mut out) = child.stdout.take() {
            let _ = out.read_to_string(&mut pressed);
        }
        // Anything else means the popup was dismissed rather than actioned.
        if pressed.trim() != "tui" {
            return;
        }
        let Some((program, rest)) = cmd.split_first() else {
            return;
        };
        if let Err(e) = Command::new(program)
            .args(rest)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            eprintln!("packetminder: cannot launch {program}: {e}");
        }
    }))
}

/// What the alert's button should run, or None to offer no button.
///
/// Split on whitespace rather than run through a shell: an alert body contains
/// attacker-influenced text, and while that text never reaches this command,
/// keeping a shell out of the notification path entirely is cheaper than
/// reasoning about whether it could.
fn tui_command(cfg: &Config) -> Option<Vec<String>> {
    let configured = cfg.tui_command.trim();
    if configured.eq_ignore_ascii_case("off") {
        return None;
    }
    if !configured.is_empty() {
        let parts: Vec<String> = configured.split_whitespace().map(String::from).collect();
        return (!parts.is_empty()).then_some(parts);
    }

    // Never offer a button that cannot work.
    if !in_path("packetminder-tui") {
        return None;
    }
    for (terminal, flag) in [
        ("konsole", "-e"),
        ("alacritty", "-e"),
        ("kitty", "-e"),
        ("foot", "-e"),
        ("xterm", "-e"),
        // gnome-terminal wants `--` where the rest want `-e`.
        ("gnome-terminal", "--"),
    ] {
        if in_path(terminal) {
            return Some(vec![terminal.into(), flag.into(), "packetminder-tui".into()]);
        }
    }
    None
}

fn in_path(name: &str) -> bool {
    let Some(path) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&path).any(|dir| dir.join(name).is_file())
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

/// How long a whois answer is reused. Allocation ownership does not move on
/// DHCP timescales, so this is generous — and it is what lets the cached
/// describe_source include the ISP, which in turn is what makes an enrichment
/// rebuild identical to the immediate alert for a repeat offender.
const WHOIS_TTL_SECS: i64 = 3600;

/// ip → (org, when). Negatives cached too, same argument as the name cache.
type WhoisCache = Mutex<HashMap<String, (Option<String>, i64)>>;

fn whois_cache() -> &'static WhoisCache {
    static CACHE: OnceLock<WhoisCache> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Names from the config, keyed by lowercase MAC or by address.
static NAMES: OnceLock<HashMap<String, String>> = OnceLock::new();

/// Install the configured names. Called once at startup — a global rather than
/// a parameter because every label site would otherwise have to be handed the
/// whole Config to look up one string.
pub fn set_names(names: HashMap<String, String>) {
    let _ = NAMES.set(names);
}

/// The name you chose for this device, if you named it.
///
/// Address first, then MAC. The MAC is the durable key — it survives a DHCP
/// reshuffle, and it is the only thing that separates two devices whose vendor
/// and firmware-published name are identical.
fn chosen_name(ip: &str) -> Option<String> {
    let names = NAMES.get()?;
    if names.is_empty() {
        return None;
    }
    if let Some(name) = names.get(ip) {
        return Some(name.clone());
    }
    let mac = neighbour_mac(ip)?.to_lowercase();
    names.get(&mac).cloned()
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
///
/// Cache-only: consults the name cache but never shells out to a resolver, so
/// it is safe on the detector loop. The enrichment threads are what fill the
/// cache; until one has, a source shows as its vendor or bare address.
pub fn device_label_cached(ip: &str) -> String {
    // A name you chose beats anything that can be discovered, always.
    if let Some(name) = chosen_name(ip) {
        return format!("{name} ({ip})");
    }

    let named = hostname_cached(ip);
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

/// Split a device into what the network calls it and what we worked out.
///
/// Returns `("X01000EKSRNP.local (10.3.193.195)", Some("Roku CRR · Roku"))`.
///
/// The first is the raw network identity, and it goes first because it is the
/// actionable half: it is what you paste into a firewall rule, a capture
/// filter, or a grep. The second is everything derived — the name you chose,
/// the vendor behind the MAC — which is what tells you what the thing actually
/// is. Collapsing them into one label, as this used to, always threw away
/// whichever half the reader happened to need.
///
/// This variant resolves: it may wait on `getent` (2s cap). Keep it off the
/// detector loop — that is what `identity_cached` is for.
pub fn identity(ip: &str) -> (String, Option<String>) {
    identity_at(ip, true)
}

/// `identity`, but consulting caches only — never a resolver. Safe anywhere.
pub fn identity_cached(ip: &str) -> (String, Option<String>) {
    identity_at(ip, false)
}

fn identity_at(ip: &str, resolve: bool) -> (String, Option<String>) {
    let fqdn = if resolve {
        hostname_for(ip)
    } else {
        hostname_cached(ip)
    };
    let hostname = fqdn
        .as_deref()
        .and_then(|n| n.split('.').next().map(str::to_string))
        .filter(|n| !n.is_empty());

    let primary = match &fqdn {
        Some(fqdn) => format!("{fqdn} ({ip})"),
        None => ip.to_string(),
    };

    let mut derived: Vec<String> = Vec::new();
    if let Some(chosen) = chosen_name(ip) {
        derived.push(chosen);
    }
    if let Some(vendor) = vendor_for(ip) {
        // Saying "Roku" under a hostname of "roku-living-room" is noise.
        let already_said = derived
            .iter()
            .chain(hostname.iter())
            .any(|s| s.to_lowercase().contains(&vendor.to_lowercase()));
        if !already_said {
            derived.push(vendor);
        }
    }

    let derived = (!derived.is_empty()).then(|| derived.join(" · "));
    (primary, derived)
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

/// Boilerplate the IEEE registry carries that never says which box this is.
/// Order does not matter — stripping repeats until it stops changing anything.
const VENDOR_NOISE: [&str; 30] = [
    " Inc.",
    " Inc",
    " Corp.",
    " Corp",
    " Corporation",
    " Corporate",
    " Company",
    " Co.",
    " Co",
    " Ltd.",
    " Ltd",
    " Limited",
    " LLC",
    " L.L.C.",
    " GmbH",
    " AG",
    " B.V.",
    " N.V.",
    " S.A.",
    " PLC",
    " Pte",
    " Pty",
    " Technologies",
    " Technology",
    " Electronics",
    " Electronic",
    " Systems",
    " Networks",
    " Solutions",
    " Communications",
];

/// "Roku, Inc" → "Roku". "GL Technologies (Hong Kong) Limited" → "GL".
///
/// The registry is full of legal boilerplate, place-of-incorporation
/// parentheticals and generic descriptors. None of it identifies the device,
/// and all of it costs width in a popup budgeted at two lines.
fn tidy_vendor(raw: &str) -> String {
    // "LCFC(Hefei) …" and "… (Hong Kong) Limited" both carry a parenthetical,
    // and it is never the brand.
    let mut unparenthesised = String::with_capacity(raw.len());
    let mut depth = 0usize;
    for c in raw.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            _ if depth == 0 => unparenthesised.push(c),
            _ => {}
        }
    }

    let head = unparenthesised
        .split(',')
        .next()
        .unwrap_or(&unparenthesised)
        .trim()
        .to_string();
    let mut best = head.as_str();

    // Repeat until stable. "LCFC Electronics Technology co." has to shed three
    // separate words, and a single pass strips only whichever the list reaches
    // first. Bounded so a pathological name cannot spin.
    for _ in 0..8 {
        let before = best;
        for suffix in VENDOR_NOISE {
            if let Some(stripped) = strip_suffix_ci(best, suffix) {
                let trimmed = stripped.trim_end();
                // Never strip a name down to nothing: a vendor really called
                // "Systems" keeps its name.
                if !trimmed.is_empty() {
                    best = trimmed;
                }
            }
        }
        if best == before {
            break;
        }
    }

    // Removing a parenthetical leaves a double space behind.
    let out = best.split_whitespace().collect::<Vec<_>>().join(" ");
    if out.is_empty() { raw.trim().to_string() } else { out }
}

/// `strip_suffix`, but case-insensitively — the registry writes "co., ltd" as
/// often as "Co., Ltd".
fn strip_suffix_ci<'a>(s: &'a str, suffix: &str) -> Option<&'a str> {
    let split = s.len().checked_sub(suffix.len())?;
    if !s.is_char_boundary(split) {
        return None;
    }
    let (head, tail) = s.split_at(split);
    tail.eq_ignore_ascii_case(suffix).then_some(head)
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

/// The cached hostname, or None — never a lookup. A miss here is not "no
/// name"; it is "not resolved yet", which the enrichment path fixes moments
/// later.
fn hostname_cached(ip: &str) -> Option<String> {
    let cache = name_cache().lock().ok()?;
    let (name, at) = cache.get(ip)?;
    if now_epoch() - at < NAME_TTL_SECS {
        name.clone()
    } else {
        None
    }
}

/// Context for a source address beyond its name: which network it sits on, and
/// who operates it. The name itself is already in the alert title.
///
/// `nearby` must come from `LocalNet::is_on_link`, not from the address class.
/// Asking whois about a neighbour returns a confident, correct, and thoroughly
/// misleading answer — it names whoever owns the allocation, so a machine on
/// the same switch gets reported as an ISP on the far side of the internet.
pub fn describe_source(ip: &str, nearby: bool) -> String {
    describe_source_at(ip, nearby, true)
}

/// `describe_source` without the whois: an internet source is just "internet"
/// until an enrichment thread has asked. The LAN path is unchanged — the
/// neighbour table is a local netlink dump, not a network wait.
pub fn describe_source_cached(ip: &str, nearby: bool) -> String {
    describe_source_at(ip, nearby, false)
}

fn describe_source_at(ip: &str, nearby: bool, resolve: bool) -> String {
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
        let isp = if resolve {
            whois_org(ip, 5)
        } else {
            whois_org_cached(ip)
        };
        if let Some(isp) = isp {
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

/// The cached whois answer, or None — never a lookup.
fn whois_org_cached(ip: &str) -> Option<String> {
    let cache = whois_cache().lock().ok()?;
    let (org, at) = cache.get(ip)?;
    if now_epoch() - at < WHOIS_TTL_SECS {
        org.clone()
    } else {
        None
    }
}

fn whois_org(ip: &str, timeout_secs: u64) -> Option<String> {
    if let Ok(cache) = whois_cache().lock()
        && let Some((org, at)) = cache.get(ip)
        && now_epoch() - at < WHOIS_TTL_SECS
    {
        return org.clone();
    }

    let org = whois_org_uncached(ip, timeout_secs);
    if let Ok(mut cache) = whois_cache().lock() {
        cache.insert(ip.to_string(), (org.clone(), now_epoch()));
    }
    org
}

/// whois with a hard deadline: killed and reaped on expiry, stdout drained
/// concurrently so a chatty registry cannot block the child on a full pipe.
/// Abandoning the wait, as the old with_timeout wrapper did, left a whois that
/// never exits running forever.
fn whois_org_uncached(ip: &str, timeout_secs: u64) -> Option<String> {
    let mut child = Command::new("whois")
        .arg(ip)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    let (tx, rx) = channel();
    if let Some(mut stdout) = child.stdout.take() {
        thread::spawn(move || {
            let mut text = String::new();
            let _ = std::io::Read::read_to_string(&mut stdout, &mut text);
            let _ = tx.send(text);
        });
    }

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(_) => return None,
        }
    }
    let text = rx.recv_timeout(Duration::from_secs(1)).ok()?;

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
// pulling in the libc crate. packetminder-core does the same thing for its clock
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

        // Every one of these is on the LAN this was written for, and each broke
        // an earlier version: a missing suffix, a lowercase one, a parenthetical.
        assert_eq!(tidy_vendor("Dell Inc."), "Dell");
        assert_eq!(tidy_vendor("TIBRO Corp."), "TIBRO");
        assert_eq!(tidy_vendor("GL Technologies (Hong Kong) Limited"), "GL");
        assert_eq!(
            tidy_vendor("LCFC(Hefei) Electronics Technology co., ltd"),
            "LCFC"
        );

        // Nothing to strip, and nothing that strips down to nothing.
        assert_eq!(tidy_vendor("Google"), "Google");
        assert_eq!(tidy_vendor("Inc"), "Inc");
    }
}

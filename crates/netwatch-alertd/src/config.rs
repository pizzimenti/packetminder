// =============================================================================
// config — tunables, loaded from a plain `key = value` file.
//
// Config lives at $XDG_CONFIG_HOME/netwatch/alertd.conf (default
// ~/.config/netwatch/alertd.conf). Every key is optional; anything missing
// falls back to the defaults below. Unknown keys are reported but ignored so a
// stale config never stops the service from starting.
// =============================================================================

use std::{env, fs, path::PathBuf};

// -- Data Structures ----------------------------------------------------------

pub struct Config {
    /// Seconds between interface samples.
    pub interval_secs: u64,

    // -- Asymmetry detector --
    /// Inbound bits/sec below which we never consider a flow interesting.
    pub rx_floor_bps: f64,
    /// Outbound must exceed this fraction of inbound to look like a conversation.
    pub asym_ratio: f64,
    /// How long the asymmetry must hold before alerting, in seconds.
    pub asym_sustain_secs: u64,
    /// Interfaces to skip entirely.
    pub ignore_interfaces: Vec<String>,

    // -- Blocked-flow detector --
    /// Kernel-log pattern identifying a dropped packet.
    pub block_pattern: String,
    /// Minimum logged drops before a flow is worth reporting.
    pub block_min_events: usize,
    /// Sliding window for counting drops, in seconds.
    pub block_window_secs: u64,
    /// A flow must persist at least this long to count as sustained.
    pub block_min_span_secs: u64,
    /// Destination ports to discard outright.
    ///
    /// Empty by default, and it should usually stay that way: the structural
    /// filters in `local` already remove the chatter that would otherwise want
    /// listing here. Reach for this only when one specific port is noisy for a
    /// reason those filters cannot see.
    pub ignore_ports: Vec<u16>,

    // -- Output --
    /// Minimum seconds between repeat alerts for the same subject.
    pub cooldown_secs: u64,
    /// Whether to raise desktop notifications.
    pub notify: bool,
    /// Append-only event log.
    pub log_path: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interval_secs: 10,

            // 1 Mbps floor: below this, even a fully one-sided flow is not
            // worth waking somebody up for.
            rx_floor_bps: 1_000_000.0,
            // A real download ACKs at roughly 2-10% of the inbound rate. Under
            // 5% means this host is not participating in what it is receiving.
            asym_ratio: 0.05,
            asym_sustain_secs: 60,
            // tailscale0 carries the same bytes as its underlay interface, so
            // counting it too would double-report every event.
            ignore_interfaces: vec!["lo".into(), "tailscale0".into()],

            block_pattern: "UFW BLOCK".into(),
            block_min_events: 4,
            block_window_secs: 900,
            block_min_span_secs: 120,
            ignore_ports: Vec::new(),

            cooldown_secs: 1800,
            notify: true,
            log_path: state_dir().join("alertd.log"),
        }
    }
}

// -- Loading ------------------------------------------------------------------

impl Config {
    pub fn load() -> Self {
        let mut cfg = Config::default();
        let path = config_path();
        let Ok(text) = fs::read_to_string(&path) else {
            return cfg;
        };

        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                eprintln!("{}:{}: expected `key = value`", path.display(), lineno + 1);
                continue;
            };
            let (key, value) = (key.trim(), value.trim());

            let ok = match key {
                "interval_secs" => set_u64(&mut cfg.interval_secs, value),
                "rx_floor_bps" => set_f64(&mut cfg.rx_floor_bps, value),
                "asym_ratio" => set_f64(&mut cfg.asym_ratio, value),
                "asym_sustain_secs" => set_u64(&mut cfg.asym_sustain_secs, value),
                "ignore_interfaces" => {
                    cfg.ignore_interfaces = value
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    true
                }
                "block_pattern" => {
                    cfg.block_pattern = value.to_string();
                    true
                }
                "block_min_events" => set_usize(&mut cfg.block_min_events, value),
                "block_window_secs" => set_u64(&mut cfg.block_window_secs, value),
                "block_min_span_secs" => set_u64(&mut cfg.block_min_span_secs, value),
                "ignore_ports" => {
                    // All-or-nothing: a typo in one entry silently widening the
                    // blind spot is worse than keeping the default.
                    let parsed: Option<Vec<u16>> = value
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(|s| s.parse().ok())
                        .collect();
                    match parsed {
                        Some(ports) => {
                            cfg.ignore_ports = ports;
                            true
                        }
                        None => false,
                    }
                }
                "cooldown_secs" => set_u64(&mut cfg.cooldown_secs, value),
                "notify" => {
                    cfg.notify = matches!(value, "1" | "true" | "yes" | "on");
                    true
                }
                "log_path" => {
                    cfg.log_path = PathBuf::from(expand_home(value));
                    true
                }
                _ => {
                    eprintln!("{}:{}: unknown key `{key}`", path.display(), lineno + 1);
                    true
                }
            };

            if !ok {
                eprintln!(
                    "{}:{}: `{key}` has an unparseable value `{value}`, keeping default",
                    path.display(),
                    lineno + 1
                );
            }
        }

        // A zero interval would spin the loop at 100% CPU.
        if cfg.interval_secs == 0 {
            cfg.interval_secs = 1;
        }
        cfg
    }

    /// One-line description of the active thresholds, for the startup log entry.
    pub fn summary(&self) -> String {
        let ignored = if self.ignore_ports.is_empty() {
            "none".to_string()
        } else {
            self.ignore_ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };

        format!(
            "interval={}s rx_floor={:.1}Mbps asym_ratio={:.0}% sustain={}s \
             block_min_events={} block_min_span={}s ignore_ports={ignored} \
             cooldown={}s notify={}",
            self.interval_secs,
            self.rx_floor_bps / 1_000_000.0,
            self.asym_ratio * 100.0,
            self.asym_sustain_secs,
            self.block_min_events,
            self.block_min_span_secs,
            self.cooldown_secs,
            self.notify,
        )
    }
}

// -- Paths --------------------------------------------------------------------

fn home() -> PathBuf {
    env::var_os("HOME").map(PathBuf::from).unwrap_or_default()
}

pub fn config_path() -> PathBuf {
    env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".config"))
        .join("netwatch")
        .join("alertd.conf")
}

pub fn state_dir() -> PathBuf {
    env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".local").join("state"))
        .join("netwatch")
}

fn expand_home(value: &str) -> String {
    match value.strip_prefix("~/") {
        Some(rest) => home().join(rest).to_string_lossy().into_owned(),
        None => value.to_string(),
    }
}

// -- Parsing Helpers ----------------------------------------------------------

fn set_u64(slot: &mut u64, value: &str) -> bool {
    match value.parse() {
        Ok(v) => {
            *slot = v;
            true
        }
        Err(_) => false,
    }
}

fn set_usize(slot: &mut usize, value: &str) -> bool {
    match value.parse() {
        Ok(v) => {
            *slot = v;
            true
        }
        Err(_) => false,
    }
}

fn set_f64(slot: &mut f64, value: &str) -> bool {
    match value.parse() {
        Ok(v) => {
            *slot = v;
            true
        }
        Err(_) => false,
    }
}

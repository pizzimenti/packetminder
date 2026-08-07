// =============================================================================
// config — tunables, loaded from a plain `key = value` file.
//
// Config lives at $XDG_CONFIG_HOME/packetminder/packetminder.conf (default
// ~/.config/packetminder/packetminder.conf). Every key is optional; anything missing
// falls back to the defaults below. Unknown keys are reported but ignored so a
// stale config never stops the service from starting.
// =============================================================================

use std::{collections::HashMap, env, fs, path::PathBuf};

// -- Data Structures ----------------------------------------------------------

// Clone: enrichment threads carry a copy so re-notification does not need to
// borrow the detector loop's instance across a thread boundary.
#[derive(Clone)]
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
    /// Before alerting on asymmetry, ask whether an established socket is
    /// actually reading the traffic. A fast download and a one-sided flood have
    /// the same ratio, so no threshold can separate them — only this can.
    pub socket_corroboration: bool,
    /// Fraction of an interface's inbound that sockets must account for before
    /// the traffic counts as wanted and the alert is dropped.
    pub socket_account_ratio: f64,

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

    // -- Self-blocked detector --
    /// Rolling window for judging this host's own blocked traffic, in seconds.
    pub self_window_secs: u64,
    /// Alert once its own multicast has been dropped in this many distinct
    /// minutes of the window. Minutes rather than records, because ufw's log
    /// limiter caps records per minute and would otherwise set the ceiling.
    pub self_min_active_minutes: usize,
    /// Locally-sourced *unicast* on the input path has no benign explanation,
    /// so it needs only enough records to rule out a one-off.
    pub self_unicast_min_events: u64,

    // -- Protocol counters --
    /// Watch /proc/net/snmp and /proc/net/netstat.
    pub watch_proto: bool,
    /// Datagrams per second delivered to a port with no socket, above which
    /// something is persistently talking to a port nothing serves.
    pub noports_min_rate: f64,
    /// Packets per second discarded because a receive queue was full. This one
    /// is about a local program falling behind, not about an unwanted sender.
    pub rcvbuf_min_rate: f64,
    /// How long either rate must hold before alerting, in seconds.
    pub proto_sustain_secs: u64,

    // -- Device names --
    /// Names you chose, keyed by lowercase MAC or by address.
    ///
    /// Consulted before any lookup, because it is the only source that knows
    /// which of two identical devices this is. An OUI gives the type -- two
    /// travel routers from the same maker are both "GL" -- and mDNS gives
    /// whatever the vendor's firmware felt like publishing.
    pub names: HashMap<String, String>,

    // -- IPv6 watch --
    /// Report when IPv6 addressing becomes active where there was none.
    ///
    /// A plain state-change notice, not a judgement: it is useful whether you
    /// are trying to keep IPv6 off and want to know it came back, or expect it
    /// on and want to know when it actually arrived.
    pub watch_ipv6: bool,

    // -- Output --
    /// Minimum seconds between repeat alerts for the same subject.
    pub cooldown_secs: u64,
    /// Whether to raise desktop notifications.
    pub notify: bool,
    /// Command an alert's "Open packetminder" button runs, split on whitespace —
    /// this is not a shell, so pipes and quoting will not work.
    ///
    /// Empty means detect a terminal emulator and run the TUI in it. Set it to
    /// `off` to drop the button entirely.
    pub tui_command: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interval_secs: 10,

            // 1 Mbps floor: below this, even a fully one-sided flow is not
            // worth waking somebody up for.
            rx_floor_bps: 1_000_000.0,
            // Bulk TCP with delayed ACKs sends roughly one 66-byte ack per two
            // 1514-byte frames, so a healthy download runs about 2.2% outbound.
            // 5% sat above that and caught ordinary downloads; 2% sits just
            // below it.
            //
            // This narrows the overlap rather than removing it. A download can
            // dip under 2% with large-receive-offload, and a real one-sided
            // flood can carry a little back-chatter. A ratio alone cannot
            // separate them -- that needs corroboration from whether a socket
            // actually accounts for the volume.
            asym_ratio: 0.02,
            asym_sustain_secs: 60,
            // tailscale0 carries the same bytes as its underlay interface, so
            // counting it too would double-report every event.
            ignore_interfaces: vec!["lo".into(), "tailscale0".into()],

            socket_corroboration: true,
            // Deliberately not 1.0. Sockets opening or closing mid-measurement
            // are skipped, and non-TCP traffic is never counted at all, so the
            // socket figure always reads a little low. 70% is "most of this is
            // explained" without demanding an accounting that cannot be exact.
            socket_account_ratio: 0.7,

            block_pattern: "UFW BLOCK".into(),
            block_min_events: 4,
            block_window_secs: 900,
            block_min_span_secs: 120,
            ignore_ports: Vec::new(),

            // An hour of context, alerting at half of it. The observed benign
            // case — systemd-resolved's LLMNR retries — is active in about five
            // minutes of any given hour, so this leaves real headroom rather
            // than sitting just above the noise.
            self_window_secs: 3600,
            self_min_active_minutes: 30,
            self_unicast_min_events: 4,

            watch_proto: true,
            // A handful of stray datagrams a second is ordinary on any LAN with
            // discovery protocols on it. Five a second, held for a minute, is
            // something actually pointed at this host.
            noports_min_rate: 5.0,
            // Receive-buffer loss is rarer and means more when it happens, but
            // a brief burst during a spike is normal, so it still has to hold.
            rcvbuf_min_rate: 10.0,
            proto_sustain_secs: 60,

            names: HashMap::new(),

            watch_ipv6: true,

            cooldown_secs: 1800,
            notify: true,
            tui_command: String::new(),
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
                "rx_floor_bps" => set_f64_at_least(&mut cfg.rx_floor_bps, value, 0.0),
                "asym_ratio" => set_ratio(&mut cfg.asym_ratio, value),
                "asym_sustain_secs" => set_u64(&mut cfg.asym_sustain_secs, value),
                "socket_corroboration" => {
                    cfg.socket_corroboration = matches!(value, "1" | "true" | "yes" | "on");
                    true
                }
                "socket_account_ratio" => set_ratio(&mut cfg.socket_account_ratio, value),
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
                "self_window_secs" => set_u64(&mut cfg.self_window_secs, value),
                "self_min_active_minutes" => set_usize(&mut cfg.self_min_active_minutes, value),
                "self_unicast_min_events" => set_u64(&mut cfg.self_unicast_min_events, value),
                "watch_ipv6" => {
                    cfg.watch_ipv6 = matches!(value, "1" | "true" | "yes" | "on");
                    true
                }
                "watch_proto" => {
                    cfg.watch_proto = matches!(value, "1" | "true" | "yes" | "on");
                    true
                }
                "noports_min_rate" => set_f64_at_least(&mut cfg.noports_min_rate, value, 0.0),
                "rcvbuf_min_rate" => set_f64_at_least(&mut cfg.rcvbuf_min_rate, value, 0.0),
                "proto_sustain_secs" => set_u64(&mut cfg.proto_sustain_secs, value),
                // `name <mac|ip> = <label>`, repeatable. A MAC survives a DHCP
                // reshuffle; an address is there for devices that never appear
                // in the neighbour table.
                k if k.starts_with("name ") => {
                    let subject = k["name ".len()..].trim().to_lowercase();
                    if subject.is_empty() || value.is_empty() {
                        false
                    } else {
                        cfg.names.insert(subject, value.to_string());
                        true
                    }
                }
                "cooldown_secs" => set_u64(&mut cfg.cooldown_secs, value),
                "notify" => {
                    cfg.notify = matches!(value, "1" | "true" | "yes" | "on");
                    true
                }
                "tui_command" => {
                    cfg.tui_command = value.to_string();
                    true
                }
                _ => {
                    eprintln!("{}:{}: unknown key `{key}`", path.display(), lineno + 1);
                    true
                }
            };

            if !ok {
                eprintln!(
                    "{}:{}: `{key}` has an unparseable or out-of-range value `{value}`, \
                     keeping the previous value",
                    path.display(),
                    lineno + 1
                );
            }
        }

        // A zero interval would spin the loop at 100% CPU.
        if cfg.interval_secs == 0 {
            cfg.interval_secs = 1;
        }
        // Detectors compare cooldowns against i64 epoch arithmetic. A value
        // past i64::MAX would wrap negative there and read as always-cooled;
        // clamping once here keeps every cast downstream honest. Nobody sets a
        // 292-billion-year cooldown on purpose, but a config typo can.
        cfg.cooldown_secs = cfg.cooldown_secs.min(i64::MAX as u64);
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

        let proto = if self.watch_proto {
            format!(
                "noports_min_rate={:.0}/s rcvbuf_min_rate={:.0}/s proto_sustain={}s",
                self.noports_min_rate, self.rcvbuf_min_rate, self.proto_sustain_secs,
            )
        } else {
            "proto=off".to_string()
        };

        format!(
            "interval={}s rx_floor={:.1}Mbps asym_ratio={:.0}% sustain={}s \
             socket_corroboration={} ({:.0}% accounted) \
             block_min_events={} block_min_span={}s ignore_ports={ignored} \
             self_window={}s self_min_active_minutes={} {proto} named_devices={} \
             cooldown={}s notify={}",
            self.interval_secs,
            self.rx_floor_bps / 1_000_000.0,
            self.asym_ratio * 100.0,
            self.asym_sustain_secs,
            self.socket_corroboration,
            self.socket_account_ratio * 100.0,
            self.block_min_events,
            self.block_min_span_secs,
            self.self_window_secs,
            self.self_min_active_minutes,
            self.names.len(),
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
        .join("packetminder")
        .join("packetminder.conf")
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

/// A fraction: finite and inside [0, 1]. `asym_ratio = -1` parses fine as a
/// float and then silently disables the detector it configures, which is the
/// kind of typo that should be a warning, not a behaviour.
fn set_ratio(slot: &mut f64, value: &str) -> bool {
    match value.parse::<f64>() {
        Ok(v) if v.is_finite() && (0.0..=1.0).contains(&v) => {
            *slot = v;
            true
        }
        _ => false,
    }
}

/// A magnitude: finite and at least `min`. NaN fails every comparison it later
/// feeds, which reads as "never alert" — refuse it here instead.
fn set_f64_at_least(slot: &mut f64, value: &str, min: f64) -> bool {
    match value.parse::<f64>() {
        Ok(v) if v.is_finite() && v >= min => {
            *slot = v;
            true
        }
        _ => false,
    }
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratios_reject_everything_outside_the_unit_interval() {
        let mut slot = 0.5;
        assert!(set_ratio(&mut slot, "0.02"));
        assert_eq!(slot, 0.02);

        for bad in ["-1", "1.5", "NaN", "inf", "-inf", "banana"] {
            assert!(!set_ratio(&mut slot, bad), "{bad} must be refused");
            assert_eq!(slot, 0.02, "{bad} must not overwrite the previous value");
        }
        assert!(set_ratio(&mut slot, "0"));
        assert!(set_ratio(&mut slot, "1"));
    }

    #[test]
    fn magnitudes_reject_negatives_and_nan() {
        let mut slot = 5.0;
        assert!(set_f64_at_least(&mut slot, "1000000", 0.0));
        assert_eq!(slot, 1_000_000.0);
        // "inf" is the case that actually needs is_finite(): -inf and -1 fail
        // the minimum check on their own.
        for bad in ["-1", "NaN", "inf", "-inf", "x"] {
            assert!(!set_f64_at_least(&mut slot, bad, 0.0), "{bad} must be refused");
        }
        assert_eq!(slot, 1_000_000.0);
    }
}

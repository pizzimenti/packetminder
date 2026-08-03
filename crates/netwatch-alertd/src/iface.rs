// =============================================================================
// iface — per-interface throughput sampling and the asymmetry detector.
//
// The premise: a host that is genuinely downloading also transmits. TCP sends
// ACKs, QUIC sends acks, even a UDP media client sends control traffic and
// input. Sustained inbound with near-zero outbound means packets are arriving
// that this host is not participating in — a misdirected stream, a stale peer
// still transmitting, a flood.
//
// This works purely from /proc/net/dev, so it sees traffic that connection
// tracking cannot: UDP to a closed port has no socket, no conntrack entry, and
// no row in `ss` output, but it still moves the interface counters.
// =============================================================================

use std::{
    collections::HashMap,
    fs,
    time::{Duration, Instant},
};

use crate::{
    alert::{Alert, fmt_bits, fmt_duration},
    config::Config,
};

// -- Data Structures ----------------------------------------------------------

#[derive(Clone, Copy)]
pub struct Counters {
    pub rx: u64,
    pub tx: u64,
}

#[derive(Clone, Copy)]
pub struct Rates {
    pub rx_bps: f64,
    pub tx_bps: f64,
}

pub struct AsymDetector {
    last: HashMap<String, Counters>,
    last_at: Instant,
    /// When the current run of suspicion started, per interface.
    since: HashMap<String, Instant>,
    /// When we last alerted, per interface.
    alerted: HashMap<String, Instant>,
    /// Most recent computed rates, for --status.
    pub rates: HashMap<String, Rates>,
}

// -- Sampling -----------------------------------------------------------------

/// Read cumulative rx/tx byte counters for every interface.
pub fn read_dev() -> HashMap<String, Counters> {
    let mut out = HashMap::new();
    let Ok(text) = fs::read_to_string("/proc/net/dev") else {
        return out;
    };

    // Two header lines, then "  iface: rx_bytes rx_packets ... tx_bytes ...".
    for line in text.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let fields: Vec<&str> = rest.split_whitespace().collect();
        if fields.len() < 9 {
            continue;
        }
        let (Ok(rx), Ok(tx)) = (fields[0].parse::<u64>(), fields[8].parse::<u64>()) else {
            continue;
        };
        out.insert(name.trim().to_string(), Counters { rx, tx });
    }
    out
}

// -- Detector -----------------------------------------------------------------

impl AsymDetector {
    pub fn new() -> Self {
        Self {
            last: read_dev(),
            last_at: Instant::now(),
            since: HashMap::new(),
            alerted: HashMap::new(),
            rates: HashMap::new(),
        }
    }

    /// Sample the counters and return any alerts that just became due.
    ///
    /// `hint` is a short description of concurrent firewall drops, if any — it
    /// turns "something is flooding this interface" into "and here is who".
    pub fn tick(&mut self, cfg: &Config, hint: Option<String>) -> Vec<Alert> {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_at).as_secs_f64();
        if elapsed <= 0.0 {
            return Vec::new();
        }

        let current = read_dev();
        let mut alerts = Vec::new();
        self.rates.clear();

        for (name, counters) in &current {
            if cfg.ignore_interfaces.iter().any(|i| i == name) {
                continue;
            }
            let Some(previous) = self.last.get(name) else {
                continue; // interface appeared this tick; wait for a baseline
            };

            // Counters reset when an interface goes down and back up.
            // saturating_sub turns that into a zero-rate sample rather than a
            // spike large enough to alert on.
            let rx_bps = counters.rx.saturating_sub(previous.rx) as f64 * 8.0 / elapsed;
            let tx_bps = counters.tx.saturating_sub(previous.tx) as f64 * 8.0 / elapsed;
            self.rates.insert(name.clone(), Rates { rx_bps, tx_bps });

            let one_sided = rx_bps >= cfg.rx_floor_bps && tx_bps < rx_bps * cfg.asym_ratio;
            if !one_sided {
                self.since.remove(name);
                continue;
            }

            let started = *self.since.entry(name.clone()).or_insert(now);
            let held = now.duration_since(started);
            if held < Duration::from_secs(cfg.asym_sustain_secs) {
                continue;
            }

            let cooled = self.alerted.get(name).is_none_or(|last| {
                now.duration_since(*last) >= Duration::from_secs(cfg.cooldown_secs)
            });
            if !cooled {
                continue;
            }

            self.alerted.insert(name.clone(), now);
            alerts.push(build_alert(name, rx_bps, tx_bps, held.as_secs(), hint.as_deref()));
        }

        self.last = current;
        self.last_at = now;
        alerts
    }
}

fn build_alert(
    iface: &str,
    rx_bps: f64,
    tx_bps: f64,
    held_secs: u64,
    hint: Option<&str>,
) -> Alert {
    let ratio = if rx_bps > 0.0 {
        tx_bps / rx_bps * 100.0
    } else {
        0.0
    };

    let mut body = format!(
        "Receiving {} but sending only {} ({:.1}% of inbound) for {}.\n\
         Nothing on this host appears to be answering it.",
        fmt_bits(rx_bps),
        fmt_bits(tx_bps),
        ratio,
        fmt_duration(held_secs),
    );

    match hint {
        Some(h) => body.push_str(&format!("\nFirewall is dropping: {h}")),
        None => body.push_str(&format!(
            "\nTo identify it: sudo tcpdump -i {iface} -nn -c 200"
        )),
    }

    Alert {
        kind: "asymmetric-inbound",
        key: format!("asym-{iface}"),
        title: format!("Unanswered inbound traffic on {iface}"),
        body,
        urgency: "critical",
    }
}

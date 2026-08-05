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
    collector::{self, Snapshot},
    config::Config,
    role, sockets,
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
    /// Last *distinct* collector snapshot. Held rather than overwritten every
    /// tick because the collector refreshes every 5s while this ticks every 10s
    /// — replacing it with an identical read would make the measurement window
    /// permanently zero-length.
    last_snapshot: Option<Snapshot>,
    /// Inbound bits/sec conntrack attributed over the last refresh interval.
    conntrack_rx_bps: Option<f64>,
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
            last_snapshot: collector::read(),
            conntrack_rx_bps: None,
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

        // First pass: a rate for every interface being watched. Judgement has
        // to wait until all of them are known, because when this host forwards,
        // the denominator is the whole host rather than one interface.
        let mut sampled: Vec<(String, Rates)> = Vec::new();
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
            sampled.push((name.clone(), Rates { rx_bps, tx_bps }));
        }

        // Re-read every tick rather than caching: turning on a hotspot or
        // connection sharing flips forwarding underneath a running daemon, and
        // nothing announces it.
        let routing = role::is_forwarding();
        let host_tx_bps: f64 = sampled.iter().map(|(_, r)| r.tx_bps).sum();

        // Refresh the conntrack view. Advance the baseline only when the
        // collector actually wrote a new snapshot, so the rate spans a real
        // interval instead of collapsing to nothing.
        if let Some(current) = collector::read() {
            match self.last_snapshot {
                Some(prev) => {
                    if let Some(bps) = current.reply_bps_since(&prev) {
                        self.conntrack_rx_bps = Some(bps);
                        self.last_snapshot = Some(current);
                    }
                }
                None => self.last_snapshot = Some(current),
            }
        }

        for (name, rates) in &sampled {
            // A router receives on one interface and answers on another, so
            // per-interface rx-without-tx is what a *working* router looks
            // like. Judging each interface alone would report a healthy hotspot
            // as a flood on both of its interfaces at once. Whether this host
            // answered at all is still a fair question — just at host scope.
            let answering_bps = if routing { host_tx_bps } else { rates.tx_bps };
            let one_sided =
                rates.rx_bps >= cfg.rx_floor_bps && answering_bps < rates.rx_bps * cfg.asym_ratio;
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

            // The last question before interrupting anyone: is something on
            // this host actually reading the traffic? A fast download and a
            // one-sided flood have the same ratio, so the ratio cannot tell
            // them apart -- but a socket's receive counter can.
            let by_socket = if cfg.socket_corroboration {
                sockets::established_rx_bps(Duration::from_secs(1))
            } else {
                None
            };

            // Two sources, each blind where the other sees. `ss` is current to
            // the second but reports no byte counters for UDP, so it cannot see
            // a QUIC transfer at all. conntrack covers UDP but lags the
            // collector's 5s timer. Whichever accounts for more is the better
            // informed, so take the larger.
            //
            // Both are host-scoped rather than per-interface, so a flood on one
            // interface concurrent with a large legitimate transfer on another
            // can be masked. That is the honest limit of asking "is anything
            // here consuming this?" without per-flow attribution.
            let accounted = match (by_socket, self.conntrack_rx_bps) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (only @ Some(_), None) | (None, only @ Some(_)) => only,
                (None, None) => None,
            };

            if let Some(bps) = accounted
                && bps >= rates.rx_bps * cfg.socket_account_ratio
            {
                let via = match (by_socket, self.conntrack_rx_bps) {
                    (Some(s), Some(c)) if c > s => "conntrack accounts",
                    (Some(_), _) => "sockets account",
                    _ => "conntrack accounts",
                };
                crate::alert::log(&format!(
                    "asymmetric-inbound withheld on {name} — {via} for {} of {} inbound",
                    fmt_bits(bps),
                    fmt_bits(rates.rx_bps),
                ));
                // Re-earn the sustain window rather than taking the full
                // cooldown. A flood starting behind a long download should not
                // have to wait 30 minutes to be noticed, but re-measuring every
                // tick for the length of that download is not worth the spawns.
                self.since.remove(name);
                continue;
            }

            self.alerted.insert(name.clone(), now);
            alerts.push(build_alert(
                name,
                rates.rx_bps,
                rates.tx_bps,
                held.as_secs(),
                hint.as_deref(),
                routing,
                accounted,
            ));
        }

        self.rates = sampled.into_iter().collect();
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
    routing: bool,
    accounted: Option<f64>,
) -> Alert {
    let ratio = if rx_bps > 0.0 {
        tx_bps / rx_bps * 100.0
    } else {
        0.0
    };

    let body = format!(
        "Receiving {}, sending only {} ({:.1}%) for {}.\n{}",
        fmt_bits(rx_bps),
        fmt_bits(tx_bps),
        ratio,
        fmt_duration(held_secs),
        if routing {
            // The reader needs to know the judgement was made at host scope,
            // or the per-interface numbers above will not add up for them.
            "This host is forwarding, and no interface is passing it on."
        } else {
            "Nothing on this host appears to be answering it."
        },
    );

    // Drops that happen to overlap this window are evidence, not a cause. A
    // handful of dropped UDP packets cannot account for megabits per second,
    // and putting the two side by side in a popup invites exactly that reading.
    // Say "concurrent" and keep it out of the two lines a human actually reads.
    let mut detail = match hint {
        Some(h) => format!("Concurrent firewall drops, which may be unrelated: {h}"),
        None => format!("To identify it: sudo tcpdump -i {iface} -nn -c 200"),
    };
    if routing {
        detail.push_str(&format!(
            " Judged against this host's total output rather than {iface}'s alone, \
             because forwarding is enabled ({}) — a router answering on a different \
             interface than it received on is behaving correctly.",
            role::forwarding_ifaces().join(", ")
        ));
    }
    match accounted {
        Some(bps) => detail.push_str(&format!(
            " Sockets and conntrack together account for only {} of it, so most of this \
             is arriving unread.",
            fmt_bits(bps)
        )),
        None => detail.push_str(
            " Corroboration did not run, so whether anything is reading this is \
             unverified. Installing collector/ adds conntrack as a second source.",
        ),
    }

    Alert {
        kind: "asymmetric-inbound",
        key: format!("asym-{iface}"),
        title: format!("Unanswered inbound traffic on {iface}"),
        body,
        detail,
        urgency: "critical",
    }
}

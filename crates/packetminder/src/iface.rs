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
    /// Why conntrack contributed nothing, when it contributed nothing. Its
    /// silence proves nothing about UDP either way, but the two reasons need
    /// different words: one has a fix to prescribe, the other does not.
    conntrack_gap: Option<ConntrackGap>,
    /// Log a misconfiguration once per onset, not every tick.
    warned_blind: bool,
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
            conntrack_gap: None,
            warned_blind: false,
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
            // Installed but unable to measure. Drop any rate learned earlier:
            // accounting can be switched off under a running daemon, and a
            // stale figure would keep vouching for traffic nobody is watching.
            self.conntrack_gap = if current.conntrack_acct {
                // An empty table is an ordinary quiet moment, not a fault --
                // and prescribing a sysctl that is already set sends the reader
                // after the wrong thing.
                (current.conntrack_flows == 0).then_some(ConntrackGap::NoFlows)
            } else {
                Some(ConntrackGap::AccountingOff)
            };

            if self.conntrack_gap.is_some() {
                self.conntrack_rx_bps = None;
                // Still advance the baseline, so the first measurable sample
                // after the gap compares against a snapshot from the same side
                // of it rather than reaching back across dead time.
                self.last_snapshot = Some(current);
                if self.conntrack_gap == Some(ConntrackGap::AccountingOff) && !self.warned_blind {
                    self.warned_blind = true;
                    crate::alert::log(
                        "conntrack byte accounting is off — UDP cannot be corroborated, \
                         so streams that are being consumed may be reported as unread. \
                         Fix: sysctl -w net.netfilter.nf_conntrack_acct=1",
                    );
                }
            } else {
                self.warned_blind = false;
                match self.last_snapshot {
                    // reply_bps_since returns None when either end of the
                    // interval was unmeasurable, so a gap costs one sample of
                    // corroboration rather than producing an understated rate.
                    Some(prev) => match current.reply_bps_since(&prev) {
                        Some(bps) => {
                            self.conntrack_rx_bps = Some(bps);
                            self.last_snapshot = Some(current);
                        }
                        None if !prev.measures_bytes() => {
                            self.last_snapshot = Some(current);
                        }
                        None => {}
                    },
                    None => self.last_snapshot = Some(current),
                }
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
            let seen = Corroboration {
                by_socket,
                by_conntrack: self.conntrack_rx_bps,
                gap: self.conntrack_gap,
            };

            if let Some(bps) = seen.accounted()
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
                seen,
            ));
        }

        self.rates = sampled.into_iter().collect();
        self.last = current;
        self.last_at = now;
        alerts
    }
}

/// Why conntrack could not contribute, when it could not. The two cases need
/// different words: one is a misconfiguration with a fix to prescribe, the
/// other is an ordinary quiet moment that no sysctl will change.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ConntrackGap {
    /// nf_conntrack_acct is off, so no flow carries byte counters.
    AccountingOff,
    /// Accounting is on but the table was empty, so there was nothing to count.
    NoFlows,
}

/// What each corroboration source was able to see, kept per-source rather than
/// collapsed to a single figure.
///
/// The collapse is what made the original bug possible: one number cannot say
/// whether it came from both sources agreeing or from one source while the
/// other was blind, and the difference is the whole meaning. "Sockets accounted
/// for 2 Kbps" alongside a reporting conntrack is evidence of unread traffic;
/// the identical figure with conntrack blind is evidence of nothing at all,
/// because `ss` cannot see UDP in the first place.
#[derive(Clone, Copy, Default)]
struct Corroboration {
    /// Established-socket receive rate, when sampled. TCP only.
    by_socket: Option<f64>,
    /// conntrack reply rate, when it could be measured. Covers UDP.
    by_conntrack: Option<f64>,
    /// Set when conntrack was installed but contributed nothing, so its silence
    /// must not be read as evidence of absence.
    gap: Option<ConntrackGap>,
}

impl Corroboration {
    /// The best-informed figure available, since each source is blind where the
    /// other sees. None when nothing could measure at all.
    fn accounted(&self) -> Option<f64> {
        match (self.by_socket, self.by_conntrack) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (only @ Some(_), None) | (None, only @ Some(_)) => only,
            (None, None) => None,
        }
    }

    /// Whether UDP could be seen at all. `ss` reports no byte counters for UDP
    /// sockets, so without conntrack a consumed stream and a flood are
    /// indistinguishable -- and this is exactly the state a game or video
    /// stream lands in.
    fn udp_is_visible(&self) -> bool {
        self.by_conntrack.is_some()
    }

    /// Why conntrack contributed nothing, phrased for someone reading an alert.
    /// An empty table is not a fault and has no fix to prescribe; prescribing a
    /// sysctl that is already set would send the reader after the wrong thing.
    fn gap_explanation(&self) -> &'static str {
        match self.gap {
            Some(ConntrackGap::AccountingOff) => {
                "conntrack byte accounting is off, so enable \
                 net.netfilter.nf_conntrack_acct=1"
            }
            Some(ConntrackGap::NoFlows) => "conntrack had no tracked flows to measure",
            None => "conntrack did not report",
        }
    }
}

fn build_alert(
    iface: &str,
    rx_bps: f64,
    tx_bps: f64,
    held_secs: u64,
    hint: Option<&str>,
    routing: bool,
    seen: Corroboration,
) -> Alert {
    let ratio = if rx_bps > 0.0 {
        tx_bps / rx_bps * 100.0
    } else {
        0.0
    };

    // Only `title` and `body` reach the popup -- `detail` is journal-only -- so
    // a caveat that lives in the detail is a caveat the person being
    // interrupted never sees. When UDP could not be checked, the claim has to
    // weaken here, where it is read.
    let verified = seen.udp_is_visible();
    let body = format!(
        "Receiving {}, sending only {} ({:.1}%) for {}.\n{}",
        fmt_bits(rx_bps),
        fmt_bits(tx_bps),
        ratio,
        fmt_duration(held_secs),
        match (verified, routing) {
            // The reader needs to know the judgement was made at host scope,
            // or the per-interface numbers above will not add up for them.
            (true, true) => "This host is forwarding, and no interface is passing it on.",
            (true, false) => "Nothing on this host appears to be answering it.",
            (false, _) =>
                "Whether anything is reading this could not be checked — a video or \
                 game stream looks exactly like this.",
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
    // Name only the sources that actually reported. Crediting a silent source
    // with a zero is how a consumed UDP stream gets described as unread.
    let sources = match (seen.by_socket, seen.by_conntrack) {
        (Some(_), Some(_)) => "Sockets and conntrack together account",
        (Some(_), None) => "Sockets account",
        (None, Some(_)) => "conntrack accounts",
        (None, None) => "",
    };
    match seen.accounted() {
        Some(bps) => detail.push_str(&format!(
            " {sources} for only {} of it{}",
            fmt_bits(bps),
            if seen.udp_is_visible() {
                ", so most of this is arriving unread.".to_string()
            } else {
                // `ss` cannot see UDP, so a socket figure alone rules nothing out.
                format!(
                    ", but UDP could not be checked at all: {}.",
                    seen.gap_explanation()
                )
            }
        )),
        None => detail.push_str(&match seen.gap {
            Some(_) => format!(
                " Nothing could measure this: {}. Treat the figures above as \
                 unverified until that is resolved.",
                seen.gap_explanation()
            ),
            None => " Corroboration did not run, so whether anything is reading this is \
                     unverified. Installing collector/ adds conntrack as a second source."
                .to_string(),
        }),
    }

    Alert {
        kind: "asymmetric-inbound",
        key: format!("asym-{iface}"),
        title: if verified {
            format!("Unanswered inbound traffic on {iface}")
        } else {
            format!("Unverified inbound traffic on {iface}")
        },
        body,
        detail,
        // An accusation nothing could substantiate does not earn a critical
        // interrupt. Still worth saying -- it is how the misconfiguration gets
        // noticed -- but at the urgency the evidence supports.
        urgency: if verified { "critical" } else { "normal" },
    }
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn alert_with(seen: Corroboration) -> Alert {
        build_alert("wlp1s0", 10_000_000.0, 30_000.0, 60, None, false, seen)
    }

    /// The popup carries only title and body -- detail is journal-only -- so a
    /// caveat that lives in the detail is one the interrupted person never
    /// reads. This is the Moonlight case: a consumed UDP stream, `ss` blind to
    /// UDP by construction, conntrack unable to measure.
    #[test]
    fn a_blind_alert_does_not_accuse_in_the_part_the_user_sees() {
        let a = alert_with(Corroboration {
            by_socket: Some(2_000.0),
            by_conntrack: None,
            gap: Some(ConntrackGap::AccountingOff),
        });

        assert!(!a.title.contains("Unanswered"), "title: {}", a.title);
        assert!(!a.body.contains("Nothing on this host"), "body: {}", a.body);
        assert!(a.body.contains("could not be checked"), "body: {}", a.body);
        // An unsubstantiated accusation does not earn a critical interrupt.
        assert_eq!(a.urgency, "normal");
        // Only the source that actually reported may be named.
        assert!(a.detail.contains("Sockets account"), "detail: {}", a.detail);
        assert!(!a.detail.contains("and conntrack together"));
    }

    /// With both sources reporting, the original wording and urgency stand --
    /// the fix must not defang a corroborated finding.
    #[test]
    fn a_corroborated_alert_still_accuses() {
        let a = alert_with(Corroboration {
            by_socket: Some(2_000.0),
            by_conntrack: Some(1_000.0),
            gap: None,
        });

        assert!(a.title.contains("Unanswered"));
        assert!(a.body.contains("Nothing on this host appears to be answering it."));
        assert_eq!(a.urgency, "critical");
        assert!(a.detail.contains("Sockets and conntrack together account"));
        assert!(a.detail.contains("arriving unread"));
    }

    /// An empty conntrack table is an ordinary quiet moment, not a
    /// misconfiguration -- prescribing a sysctl that is already set sends the
    /// reader after the wrong thing.
    #[test]
    fn an_empty_table_is_not_reported_as_a_disabled_sysctl() {
        let a = alert_with(Corroboration {
            by_socket: None,
            by_conntrack: None,
            gap: Some(ConntrackGap::NoFlows),
        });

        assert!(a.detail.contains("no tracked flows"), "detail: {}", a.detail);
        assert!(
            !a.detail.contains("nf_conntrack_acct"),
            "must not prescribe a sysctl that is already on: {}",
            a.detail
        );
    }

    /// conntrack alone must not be described as sockets having reported.
    #[test]
    fn conntrack_alone_is_named_alone() {
        let a = alert_with(Corroboration {
            by_socket: None,
            by_conntrack: Some(1_500.0),
            gap: None,
        });

        assert!(a.detail.contains("conntrack accounts"), "detail: {}", a.detail);
        assert!(!a.detail.contains("Sockets"));
        assert_eq!(a.urgency, "critical");
    }
}

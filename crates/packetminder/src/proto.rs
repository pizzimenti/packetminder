// =============================================================================
// proto — protocol-level counters from /proc/net/snmp and /proc/net/netstat.
//
// The other detectors infer "nothing wanted this traffic" from the outside: an
// interface receiving without answering, or the firewall logging what it threw
// away. The kernel keeps the same judgement directly, and these are the two
// counters worth watching:
//
//   Udp.NoPorts        datagrams delivered to a port with no socket. This is
//                      the premise of this whole daemon, counted at the source
//                      -- and unlike the drop log it also covers traffic the
//                      firewall *allows* through to a dead port, which nothing
//                      else here can see.
//   Udp.RcvbufErrors   datagrams discarded because a socket's receive queue was
//                      full. A different failure entirely: something IS
//                      listening, and it cannot keep up. Invisible to every
//                      other detector, because from the outside it looks like
//                      traffic being consumed normally.
//
// TcpExt.ListenDrops and ListenOverflows are the TCP equivalents of the second:
// connections dropped because an accept queue was full.
//
// Counters are monotonic since boot, so everything here is a delta over the
// sampling interval. A counter that moves backwards means it was reset, which
// is treated as "start again" rather than as a negative rate.
// =============================================================================

use std::{collections::HashMap, fs};

use crate::{alert::Alert, config::Config};

// -- Data Structures ----------------------------------------------------------

/// The counters this detector watches, sampled at one instant.
#[derive(Clone, Copy)]
struct Sample {
    at: i64,
    no_ports: u64,
    rcvbuf_errors: u64,
    listen_drops: u64,
}

pub struct ProtoDetector {
    last: Option<Sample>,
    /// Seconds each condition has held continuously, so a brief spike from one
    /// port scan or one busy moment does not raise anything.
    no_ports_held: u64,
    overflow_held: u64,
    /// When each condition last alerted. Without this the detector re-fired
    /// every sustain window — one popup a minute for as long as a condition
    /// held, where every other detector holds its tongue for `cooldown_secs`.
    no_ports_alerted: Option<i64>,
    overflow_alerted: Option<i64>,
}

impl Default for ProtoDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtoDetector {
    pub fn new() -> Self {
        Self {
            last: None,
            no_ports_held: 0,
            overflow_held: 0,
            no_ports_alerted: None,
            overflow_alerted: None,
        }
    }

    pub fn tick(&mut self, cfg: &Config) -> Vec<Alert> {
        let now = crate::alert::now_epoch();
        let current = Sample {
            at: now,
            no_ports: counter("Udp.NoPorts"),
            rcvbuf_errors: counter("Udp.RcvbufErrors"),
            listen_drops: counter("TcpExt.ListenDrops") + counter("TcpExt.ListenOverflows"),
        };
        self.evaluate(cfg, now, current)
    }

    /// The judgement half of `tick`, split from the sampling half so tests can
    /// drive it with synthetic counters and a synthetic clock.
    fn evaluate(&mut self, cfg: &Config, now: i64, current: Sample) -> Vec<Alert> {
        let Some(prev) = self.last.replace(current) else {
            // First tick has nothing to subtract from.
            return Vec::new();
        };

        let elapsed = (current.at - prev.at).max(1) as f64;
        let no_ports_rate = delta(prev.no_ports, current.no_ports) as f64 / elapsed;
        let overflow_rate = (delta(prev.rcvbuf_errors, current.rcvbuf_errors)
            + delta(prev.listen_drops, current.listen_drops)) as f64
            / elapsed;

        let mut alerts = Vec::new();
        let step = cfg.interval_secs;

        let cooled = |alerted: Option<i64>| {
            alerted.is_none_or(|at| now - at >= cfg.cooldown_secs as i64)
        };

        if no_ports_rate >= cfg.noports_min_rate {
            self.no_ports_held += step;
            if self.no_ports_held >= cfg.proto_sustain_secs && cooled(self.no_ports_alerted) {
                self.no_ports_held = 0;
                self.no_ports_alerted = Some(now);
                alerts.push(no_listener_alert(no_ports_rate, cfg.proto_sustain_secs));
            }
        } else {
            self.no_ports_held = 0;
        }

        if overflow_rate >= cfg.rcvbuf_min_rate {
            self.overflow_held += step;
            if self.overflow_held >= cfg.proto_sustain_secs && cooled(self.overflow_alerted) {
                self.overflow_held = 0;
                self.overflow_alerted = Some(now);
                alerts.push(overflow_alert(overflow_rate, cfg.proto_sustain_secs));
            }
        } else {
            self.overflow_held = 0;
        }

        alerts
    }
}

// -- Alerts -------------------------------------------------------------------

fn no_listener_alert(rate: f64, held: u64) -> Alert {
    Alert {
        kind: "udp-no-listener",
        key: "udp-no-listener".to_string(),
        title: format!("{rate:.0} datagrams/s arriving for ports nothing is listening on"),
        body: format!(
            "Sustained for {held}s.\n\
             The kernel is discarding them — no socket is bound to those ports."
        ),
        detail: "Counted by Udp.NoPorts in /proc/net/snmp, which unlike the firewall log \
                 also covers traffic ufw allows through to a dead port. To see who is \
                 sending it: sudo tcpdump -nn udp, and look for destination ports that \
                 `ss -uan` shows nothing bound to."
            .to_string(),
        urgency: "normal",
        popup: true,
    }
}

fn overflow_alert(rate: f64, held: u64) -> Alert {
    Alert {
        kind: "receive-overflow",
        key: "receive-overflow".to_string(),
        title: format!("Dropping {rate:.0} packets/s that this host asked for"),
        body: format!(
            "Sustained for {held}s.\n\
             A socket's receive queue is full — something here cannot keep up."
        ),
        detail: "Counted by Udp.RcvbufErrors and TcpExt.ListenDrops/ListenOverflows. This is \
                 the opposite of an unwanted flood: the traffic was wanted and a local \
                 program is too slow, or its buffer too small, to take it. `ss -tuam` shows \
                 which socket is backed up."
            .to_string(),
        urgency: "critical",
        popup: true,
    }
}

// -- Reading ------------------------------------------------------------------

/// One counter, addressed as `Section.Field` — e.g. `Udp.NoPorts`.
///
/// Missing counters read as zero. Kernels differ in which they expose, and a
/// detector that panicked on an absent field would be a liability.
fn counter(key: &str) -> u64 {
    all_counters().get(key).copied().unwrap_or(0)
}

fn all_counters() -> HashMap<String, u64> {
    let mut out = HashMap::new();
    for path in ["/proc/net/snmp", "/proc/net/netstat"] {
        merge_counters(path, &mut out);
    }
    out
}

/// Both files are pairs of lines: a header naming the fields, then the values,
/// each prefixed with the same section name.
///
///   Udp: InDatagrams NoPorts InErrors ...
///   Udp: 660285      155     15664    ...
fn merge_counters(path: &str, out: &mut HashMap<String, u64>) {
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    let mut lines = text.lines();
    while let (Some(head), Some(values)) = (lines.next(), lines.next()) {
        let (Some((section, names)), Some((vsection, nums))) =
            (head.split_once(':'), values.split_once(':'))
        else {
            continue;
        };
        // A header must be followed by its own values; anything else means the
        // file is not shaped the way this expects, so skip rather than guess.
        if section != vsection {
            continue;
        }
        for (name, num) in names.split_whitespace().zip(nums.split_whitespace()) {
            if let Ok(v) = num.parse::<u64>() {
                out.insert(format!("{section}.{name}"), v);
            }
        }
    }
}

/// Counters are monotonic until they are not: a reboot, or a module reload,
/// restarts them at zero. Going backwards means "reset", not "negative rate".
fn delta(prev: u64, current: u64) -> u64 {
    current.saturating_sub(prev)
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_paired_header_and_value_lines() {
        let mut out = HashMap::new();
        let text = "Udp: InDatagrams NoPorts InErrors\nUdp: 660285 155 15664\n";
        // merge_counters reads a path, so exercise the same parse inline.
        let mut lines = text.lines();
        while let (Some(head), Some(values)) = (lines.next(), lines.next()) {
            let (Some((section, names)), Some((vsection, nums))) =
                (head.split_once(':'), values.split_once(':'))
            else {
                continue;
            };
            if section != vsection {
                continue;
            }
            for (name, num) in names.split_whitespace().zip(nums.split_whitespace()) {
                if let Ok(v) = num.parse::<u64>() {
                    out.insert(format!("{section}.{name}"), v);
                }
            }
        }
        assert_eq!(out.get("Udp.NoPorts"), Some(&155));
        assert_eq!(out.get("Udp.InErrors"), Some(&15664));
    }

    #[test]
    fn a_counter_reset_is_not_a_negative_rate() {
        assert_eq!(delta(100, 140), 40);
        // Reboot: the counter restarts below where it was.
        assert_eq!(delta(9_000_000, 12), 0);
    }

    #[test]
    fn real_counters_are_readable_and_sane() {
        // /proc/net/snmp is world-readable on every kernel this targets, which
        // is the property that lets this detector stay unprivileged.
        let all = all_counters();
        assert!(
            all.contains_key("Udp.NoPorts"),
            "Udp.NoPorts missing from /proc/net/snmp"
        );
        assert!(all.contains_key("Udp.InDatagrams"));
    }

    /// Drive the detector with a sustained condition and a synthetic clock.
    fn sample(at: i64, no_ports: u64) -> Sample {
        Sample {
            at,
            no_ports,
            rcvbuf_errors: 0,
            listen_drops: 0,
        }
    }

    #[test]
    fn a_sustained_condition_alerts_once_per_cooldown_not_once_per_minute() {
        let cfg = Config {
            interval_secs: 10,
            noports_min_rate: 5.0,
            proto_sustain_secs: 60,
            cooldown_secs: 1800,
            ..Config::default()
        };
        let mut d = ProtoDetector::new();
        let base = 1_785_900_000;

        // 100 datagrams every 10s tick is 10/s, well over the 5/s threshold.
        // Run 200 ticks: 1990 seconds of sustained condition.
        let mut fired_at: Vec<i64> = Vec::new();
        for i in 0..200 {
            let at = base + i * 10;
            if !d.evaluate(&cfg, at, sample(at, (i as u64) * 100)).is_empty() {
                fired_at.push(at);
            }
        }

        // First alert once sustain is reached at t=+60. The second cannot come
        // before +1860 — the full configured cooldown after the first — and
        // lands exactly there, because the sustain stays banked while the
        // cooldown holds. Asserting the timestamps, not just the count: a
        // regression to a shorter cooldown would still produce two alerts.
        assert_eq!(
            fired_at,
            vec![base + 60, base + 1860],
            "second alert must wait out the full cooldown, then land immediately"
        );
    }

    #[test]
    fn a_condition_that_stops_resets_the_sustain_window() {
        let cfg = Config {
            interval_secs: 10,
            noports_min_rate: 5.0,
            proto_sustain_secs: 60,
            ..Config::default()
        };
        let mut d = ProtoDetector::new();
        let base = 1_785_900_000;

        // Five hot ticks (50s held) — just short of the 60s sustain.
        for i in 0..5 {
            let at = base + i * 10;
            assert!(d.evaluate(&cfg, at, sample(at, (i as u64) * 100)).is_empty());
        }
        // One quiet tick resets the run...
        let at = base + 50;
        assert!(d.evaluate(&cfg, at, sample(at, 400)).is_empty());
        // ...so five more hot ticks still do not reach sustain.
        for i in 6..11 {
            let at = base + i * 10;
            let alerts = d.evaluate(&cfg, at, sample(at, (i as u64) * 100));
            assert!(alerts.is_empty(), "sustain must restart after a quiet tick");
        }
    }
}

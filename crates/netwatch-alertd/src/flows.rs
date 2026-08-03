// =============================================================================
// flows — firewall-drop detection, sourced from the kernel log.
//
// ufw logs every dropped packet it is configured to log. One drop is noise: a
// stray scan, a late retransmit, an mDNS packet from a neighbour. The same
// (source, protocol, destination port) being dropped over and over for minutes
// is somebody transmitting into a host that is not listening — which is
// precisely the failure that is invisible everywhere else, because a silent
// DROP gives the sender no feedback at all.
//
// Reading the journal costs nothing and needs no privileges beyond membership
// in a group that can read kernel messages.
// =============================================================================

use std::{
    collections::{HashMap, VecDeque},
    io::{BufRead, BufReader},
    process::{Command, Stdio},
    sync::mpsc::{Receiver, channel},
    thread,
    time::Duration,
};

use crate::{
    alert::{self, Alert, describe_source, fmt_duration, now_epoch, port_in_use},
    config::Config,
};

// -- Data Structures ----------------------------------------------------------

#[derive(Clone)]
pub struct BlockEvent {
    pub ts: i64,
    pub iface: String,
    pub src: String,
    pub proto: String,
    pub sport: u16,
    pub dport: u16,
    /// IP total length, i.e. bytes on the wire for this packet.
    pub len: u64,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src: String,
    pub proto: String,
    pub dport: u16,
}

struct FlowState {
    /// Timestamps of drops inside the current window.
    times: VecDeque<i64>,
    /// Total drops observed since this flow was first seen.
    total: u64,
    first: i64,
    last: i64,
    iface: String,
    sport: u16,
    bytes: u64,
    alerted_at: Option<i64>,
}

pub struct FlowTracker {
    flows: HashMap<FlowKey, FlowState>,
}

// -- Journal Follower ---------------------------------------------------------

/// Tail the kernel log for drop records, forwarding parsed events.
///
/// The reader lives in its own thread and restarts journalctl if it ever exits,
/// so a log rotation or a systemd restart does not silently end monitoring.
pub fn spawn_follower(pattern: &str) -> Receiver<BlockEvent> {
    let (tx, rx) = channel();
    let pattern = pattern.to_string();

    thread::spawn(move || {
        loop {
            let child = Command::new("journalctl")
                .args([
                    "-k", "-f", "-n", "0", "-o", "short-iso", "--no-pager", "--grep", &pattern,
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn();

            match child {
                Ok(mut proc) => {
                    if let Some(stdout) = proc.stdout.take() {
                        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                            if let Some(event) = parse_line(&line)
                                && tx.send(event).is_err()
                            {
                                return; // main loop is gone; stop following
                            }
                        }
                    }
                    let _ = proc.wait();
                }
                Err(e) => eprintln!("netwatch-alertd: cannot run journalctl: {e}"),
            }

            // journalctl exited. Back off before retrying so a persistent
            // failure does not become a spawn loop.
            thread::sleep(Duration::from_secs(30));
        }
    });

    rx
}

/// Pull the key=value fields out of one kernel drop record.
pub fn parse_line(line: &str) -> Option<BlockEvent> {
    let mut fields: HashMap<&str, &str> = HashMap::new();
    for token in line.split_whitespace() {
        if let Some((key, value)) = token.split_once('=') {
            // LEN appears twice (IP header, then transport). First wins, which
            // is the one that counts bytes on the wire.
            fields.entry(key).or_insert(value);
        }
    }

    let src = (*fields.get("SRC")?).to_string();
    let proto = (*fields.get("PROTO")?).to_string();

    // Timestamps come from the journal itself so that replaying history lands
    // events at the time they actually happened.
    let ts = line
        .split_whitespace()
        .next()
        .and_then(parse_iso_epoch)
        .unwrap_or_else(now_epoch);

    Some(BlockEvent {
        ts,
        iface: fields.get("IN").unwrap_or(&"?").to_string(),
        src,
        proto,
        sport: fields.get("SPT").and_then(|v| v.parse().ok()).unwrap_or(0),
        dport: fields.get("DPT").and_then(|v| v.parse().ok()).unwrap_or(0),
        len: fields.get("LEN").and_then(|v| v.parse().ok()).unwrap_or(0),
    })
}

// -- Tracker ------------------------------------------------------------------

impl FlowTracker {
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
        }
    }

    pub fn record(&mut self, event: BlockEvent) {
        let key = FlowKey {
            src: event.src.clone(),
            proto: event.proto.clone(),
            dport: event.dport,
        };

        let state = self.flows.entry(key).or_insert_with(|| FlowState {
            times: VecDeque::new(),
            total: 0,
            first: event.ts,
            last: event.ts,
            iface: event.iface.clone(),
            sport: event.sport,
            bytes: 0,
            alerted_at: None,
        });

        state.times.push_back(event.ts);
        state.total += 1;
        state.bytes += event.len;
        state.last = event.ts;
        state.iface = event.iface;
        state.sport = event.sport;
    }

    pub fn tick(&mut self, cfg: &Config) -> Vec<Alert> {
        self.tick_at(cfg, now_epoch())
    }

    /// Evaluate every tracked flow as of `now`.
    ///
    /// Taking the clock as a parameter is what makes --replay possible: the
    /// same code path runs over historical events at their original times.
    pub fn tick_at(&mut self, cfg: &Config, now: i64) -> Vec<Alert> {
        let window = cfg.block_window_secs as i64;
        let mut alerts = Vec::new();
        let mut finished: Vec<FlowKey> = Vec::new();

        for (key, state) in self.flows.iter_mut() {
            while let Some(front) = state.times.front() {
                if now - front > window {
                    state.times.pop_front();
                } else {
                    break;
                }
            }

            // Nothing recent: the flow has stopped.
            if state.times.is_empty() {
                if now - state.last > window {
                    if state.alerted_at.is_some() {
                        alert::log(
                            cfg,
                            &format!(
                                "blocked-flow-ended — {} → {}/{} stopped after {} ({} drops logged)",
                                key.src,
                                key.proto.to_lowercase(),
                                key.dport,
                                fmt_duration((state.last - state.first).max(0) as u64),
                                state.total,
                            ),
                        );
                    }
                    finished.push(key.clone());
                }
                continue;
            }

            let span = state.last - *state.times.front().unwrap_or(&state.last);
            let sustained = state.times.len() >= cfg.block_min_events
                && span >= cfg.block_min_span_secs as i64;
            if !sustained {
                continue;
            }

            let cooled = state
                .alerted_at
                .is_none_or(|last| now - last >= cfg.cooldown_secs as i64);
            if !cooled {
                continue;
            }

            state.alerted_at = Some(now);
            alerts.push(build_alert(key, state, now));
        }

        for key in finished {
            self.flows.remove(&key);
        }
        alerts
    }

    /// Short description of currently-active dropped flows, for cross-referencing
    /// with an interface-level alert.
    pub fn recent_summary(&self, limit: usize) -> Option<String> {
        let mut active: Vec<(&FlowKey, &FlowState)> = self
            .flows
            .iter()
            .filter(|(_, s)| !s.times.is_empty())
            .collect();
        if active.is_empty() {
            return None;
        }

        active.sort_by(|a, b| b.1.times.len().cmp(&a.1.times.len()));
        let described: Vec<String> = active
            .iter()
            .take(limit)
            .map(|(k, s)| {
                format!(
                    "{} → {}/{} ({} drops)",
                    k.src,
                    k.proto.to_lowercase(),
                    k.dport,
                    s.times.len()
                )
            })
            .collect();

        Some(described.join("; "))
    }
}

fn build_alert(key: &FlowKey, state: &FlowState, now: i64) -> Alert {
    let proto = key.proto.to_lowercase();
    let duration = fmt_duration((now - state.first).max(0) as u64);
    let listening = port_in_use(&key.proto, key.dport);

    let mut body = format!(
        "{} drops logged over {} on {}, still going.\n",
        state.total, duration, state.iface,
    );

    if listening {
        body.push_str(&format!(
            "Something IS listening on {proto}/{} — the firewall is blocking traffic \
             a local service wants.\n",
            key.dport
        ));
    } else {
        body.push_str(&format!(
            "Nothing is listening on {proto}/{}. The sender is getting no feedback \
             because the drop is silent.\n",
            key.dport
        ));
    }

    body.push_str(&format!("Source: {}", describe_source(&key.src)));
    if state.sport != 0 {
        body.push_str(&format!(" from {proto}/{}", state.sport));
    }

    Alert {
        kind: "blocked-flow",
        key: format!("flow-{}-{}-{}", key.src, proto, key.dport),
        title: format!("{} is flooding {proto}/{}", key.src, key.dport),
        body,
        urgency: "critical",
    }
}

// -- Timestamp Parsing --------------------------------------------------------

/// Parse a journal short-iso timestamp such as `2026-08-03T00:53:29-07:00`.
pub fn parse_iso_epoch(s: &str) -> Option<i64> {
    if s.len() < 19 {
        return None;
    }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: i64 = s.get(5..7)?.parse().ok()?;
    let day: i64 = s.get(8..10)?.parse().ok()?;
    let hour: i64 = s.get(11..13)?.parse().ok()?;
    let minute: i64 = s.get(14..16)?.parse().ok()?;
    let second: i64 = s.get(17..19)?.parse().ok()?;

    let mut epoch =
        days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second;

    // Trailing zone offset, if present, converts local time back to UTC.
    let rest = s.get(19..).unwrap_or("");
    if let Some(pos) = rest.find(['+', '-']) {
        let sign = if rest.as_bytes()[pos] == b'-' { -1 } else { 1 };
        let offset = rest.get(pos + 1..).unwrap_or("");
        let off_hours: i64 = offset.get(0..2)?.parse().ok()?;
        let off_minutes: i64 = offset
            .get(3..5)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        epoch -= sign * (off_hours * 3_600 + off_minutes * 60);
    }

    Some(epoch)
}

/// Days since the Unix epoch for a civil date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_shifted = (month + 9) % 12;
    let day_of_year = (153 * month_shifted + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "2026-08-03T00:50:53-07:00 ithilien kernel: [UFW BLOCK] IN=wlp1s0 OUT= \
        MAC=3c:3b:ad:16:b7:30:18:db:f2:4d:bb:ee:08:00 SRC=10.3.59.7 DST=10.3.153.246 LEN=1436 \
        TOS=0x00 PREC=0xA0 TTL=128 ID=40959 PROTO=UDP SPT=47998 DPT=37366 LEN=1416";

    #[test]
    fn parses_a_real_drop_record() {
        let event = parse_line(SAMPLE).expect("should parse");
        assert_eq!(event.src, "10.3.59.7");
        assert_eq!(event.iface, "wlp1s0");
        assert_eq!(event.proto, "UDP");
        assert_eq!(event.sport, 47998);
        assert_eq!(event.dport, 37366);
        // First LEN wins: bytes on the wire, not the UDP payload length.
        assert_eq!(event.len, 1436);
    }

    #[test]
    fn parses_timestamp_with_zone_offset() {
        // 2026-08-03T00:50:53-07:00 == 2026-08-03T07:50:53Z
        let epoch = parse_iso_epoch("2026-08-03T00:50:53-07:00").expect("should parse");
        assert_eq!(epoch, 1_785_743_453);
    }

    #[test]
    fn ignores_lines_without_addresses() {
        assert!(parse_line("2026-08-03T00:50:53-07:00 ithilien kernel: nothing here").is_none());
    }

    #[test]
    fn sustained_flow_alerts_and_brief_flow_does_not() {
        let cfg = Config {
            block_min_events: 4,
            block_min_span_secs: 120,
            ..Config::default()
        };

        let mut tracker = FlowTracker::new();
        let base = 1_785_743_453;
        for i in 0..6 {
            tracker.record(BlockEvent {
                ts: base + i * 40,
                iface: "wlp1s0".into(),
                src: "10.3.59.7".into(),
                proto: "UDP".into(),
                sport: 47998,
                dport: 37366,
                len: 1436,
            });
        }
        assert_eq!(tracker.tick_at(&cfg, base + 200).len(), 1);

        let mut brief = FlowTracker::new();
        for i in 0..3 {
            brief.record(BlockEvent {
                ts: base + i,
                iface: "wlp1s0".into(),
                src: "10.3.59.8".into(),
                proto: "UDP".into(),
                sport: 1234,
                dport: 5678,
                len: 100,
            });
        }
        assert!(brief.tick_at(&cfg, base + 3).is_empty());
    }
}

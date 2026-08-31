// =============================================================================
// selfblock — traffic this host sends that its own firewall drops.
//
// `local` filters these records out of the blocked-flow detector, because that
// detector answers "who is transmitting into a port nothing is listening on"
// and the answer here is "we are". Filtering them there was right. Discarding
// them entirely was not: over 7 days, 361 of 4287 ufw records on this machine —
// 8.4% — were locally generated, and that is worth knowing for three reasons.
//
//   1. It consumes the log budget. ufw rate-limits its own logging, which is
//      why a 2.7 Mbps flood produced 34 records. Every self-inflicted record
//      is one a real event does not get.
//   2. It proves the firewall drops that traffic inbound too. The looped copy
//      and a peer's reply take the same path, so if mDNS discovery is supposed
//      to work here, this is how you learn that it cannot.
//   3. Some of it is genuinely wrong. Benign loopback is always addressed to a
//      multicast or broadcast group. Locally-sourced *unicast* arriving on the
//      input path is a routing loop, a misconfigured tunnel, or a spoofed
//      source — none of which should be silent.
//
// The threshold counts distinct minutes with activity, not records. ufw's
// limiter caps records per minute, so a record count measures the limiter more
// than the traffic; which minutes saw activity survives it. Bursty-but-sparse
// chatter (LLMNR: three packets, then eight quiet minutes) stays well under,
// while a program stuck in a retry loop is active in nearly every minute.
// =============================================================================

use std::collections::{HashMap, HashSet, VecDeque};

use crate::{
    alert::{Alert, fmt_bytes, fmt_duration},
    config::Config,
    flows::BlockEvent,
};

// -- Data Structures ----------------------------------------------------------

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SelfKey {
    pub dst: String,
    pub proto: String,
    pub dport: u16,
}

struct SelfState {
    /// Minute buckets inside the window that saw at least one drop.
    minutes: VecDeque<i64>,
    seen: HashSet<i64>,
    total: u64,
    bytes: u64,
    first: i64,
    last: i64,
    iface: String,
    /// Destination was a single host rather than a group — the shape that
    /// cannot be explained by ordinary multicast loopback.
    unicast: bool,
    alerted_at: Option<i64>,
}

#[derive(Default)]
pub struct SelfBlockTracker {
    flows: HashMap<SelfKey, SelfState>,
}

// -- Tracker ------------------------------------------------------------------

impl SelfBlockTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, event: &BlockEvent, unicast: bool) {
        let key = SelfKey {
            dst: event.dst.clone(),
            proto: event.proto.clone(),
            dport: event.dport,
        };

        let state = self.flows.entry(key).or_insert_with(|| SelfState {
            minutes: VecDeque::new(),
            seen: HashSet::new(),
            total: 0,
            bytes: 0,
            first: event.ts,
            last: event.ts,
            iface: event.iface.clone(),
            unicast,
            alerted_at: None,
        });

        let minute = event.ts.div_euclid(60);
        if state.seen.insert(minute) {
            state.minutes.push_back(minute);
        }
        state.total += 1;
        state.bytes += event.len;
        state.last = event.ts;
        state.iface = event.iface.clone();
        // A key that ever carries unicast keeps that classification: the
        // interesting case must not be masked by later multicast on the same
        // destination port.
        state.unicast |= unicast;
    }

    pub fn tick_at(&mut self, cfg: &Config, now: i64) -> Vec<Alert> {
        let window = cfg.self_window_secs as i64;
        let mut alerts = Vec::new();
        let mut finished: Vec<SelfKey> = Vec::new();

        for (key, state) in self.flows.iter_mut() {
            while let Some(&front) = state.minutes.front() {
                if now - front * 60 > window {
                    state.minutes.pop_front();
                    state.seen.remove(&front);
                } else {
                    break;
                }
            }

            // Nothing inside the window: this stopped.
            if state.minutes.is_empty() {
                finished.push(key.clone());
                continue;
            }

            let due = if state.unicast {
                state.total >= cfg.self_unicast_min_events
            } else {
                state.minutes.len() >= cfg.self_min_active_minutes
            };
            if !due {
                continue;
            }

            let cooled = state
                .alerted_at
                .is_none_or(|last| now - last >= cfg.cooldown_secs as i64);
            if !cooled {
                continue;
            }

            state.alerted_at = Some(now);
            alerts.push(build_alert(key, state, cfg, now));
        }

        for key in finished {
            self.flows.remove(&key);
        }
        alerts
    }

    /// One line describing everything currently being dropped, for the periodic
    /// log entry. This is what keeps sub-threshold self-traffic visible instead
    /// of merely filtered.
    pub fn summary(&self) -> Option<String> {
        if self.flows.is_empty() {
            return None;
        }

        let mut described: Vec<(usize, String)> = self
            .flows
            .iter()
            .map(|(k, s)| {
                (
                    s.minutes.len(),
                    format!(
                        "{} → {}/{} ({} drops in {} active minute(s))",
                        k.dst,
                        k.proto.to_lowercase(),
                        k.dport,
                        s.total,
                        s.minutes.len()
                    ),
                )
            })
            .collect();

        described.sort_by(|a, b| b.0.cmp(&a.0));
        Some(
            described
                .into_iter()
                .map(|(_, text)| text)
                .collect::<Vec<_>>()
                .join("; "),
        )
    }
}

fn build_alert(key: &SelfKey, state: &SelfState, cfg: &Config, now: i64) -> Alert {
    let proto = key.proto.to_lowercase();
    let duration = fmt_duration((now - state.first).max(0) as u64);

    let (title, body, detail, urgency) = if state.unicast {
        (
            format!("This host is sending blocked traffic to {}", key.dst),
            format!(
                "{} drops over {} on {}, to {}/{}.\n\
                 Addressed to one host rather than to a group.",
                state.total, duration, state.iface, proto, key.dport,
            ),
            format!(
                "{} logged. Traffic this host sent should not be arriving on its own \
                 input path unless something is looping it back: a routing loop, a \
                 misconfigured tunnel, or a spoofed source address.",
                fmt_bytes(state.bytes),
            ),
            "critical",
        )
    } else {
        (
            format!("This host's own {proto}/{} traffic is blocked", key.dport),
            format!(
                "Active in {} of the last {} minutes on {}.\n\
                 The firewall is dropping multicast this host sends to {}.",
                state.minutes.len(),
                cfg.self_window_secs / 60,
                state.iface,
                key.dst,
            ),
            format!(
                "{} drops, {}. Nothing external is involved — allow it, or stop whatever \
                 keeps sending it. Inbound replies to {proto}/{} take the same path, so \
                 they are being dropped too.",
                state.total,
                fmt_bytes(state.bytes),
                key.dport,
            ),
            "normal",
        )
    };

    Alert {
        kind: "self-blocked",
        key: format!("self-{}-{}-{}", key.dst, proto, key.dport),
        title,
        body,
        detail,
        urgency,
        popup: true,
    }
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn event(ts: i64, dst: &str, dport: u16) -> BlockEvent {
        BlockEvent {
            ts,
            iface: "wlp1s0".into(),
            src: "10.3.153.246".into(),
            dst: dst.into(),
            proto: "UDP".into(),
            sport: 5355,
            dport,
            len: 54,
        }
    }

    const BASE: i64 = 1_785_777_302;

    #[test]
    fn sparse_multicast_chatter_stays_quiet() {
        let cfg = Config::default();
        let mut tracker = SelfBlockTracker::new();

        // The real LLMNR pattern: three packets, then eight quiet minutes,
        // for a full hour. Far more records than the flood detector's
        // threshold, but active in only a handful of distinct minutes.
        for burst in 0..8 {
            for packet in 0..3 {
                tracker.record(&event(BASE + burst * 480 + packet, "224.0.0.252", 5355), false);
            }
        }

        assert!(tracker.tick_at(&cfg, BASE + 3600).is_empty());
    }

    #[test]
    fn a_retry_loop_alerts() {
        let cfg = Config::default();
        let mut tracker = SelfBlockTracker::new();

        // Something stuck: at least one record in every minute for an hour.
        // ufw's limiter caps how many, which is exactly why the threshold
        // counts minutes instead.
        for minute in 0..60 {
            tracker.record(&event(BASE + minute * 60, "224.0.0.252", 5355), false);
        }

        let alerts = tracker.tick_at(&cfg, BASE + 3600);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, "self-blocked");
        assert_eq!(alerts[0].urgency, "normal");
    }

    #[test]
    fn self_sourced_unicast_alerts_immediately_and_loudly() {
        let cfg = Config::default();
        let mut tracker = SelfBlockTracker::new();

        // No amount of ordinary multicast loopback explains this shape, so it
        // does not wait for a sustained pattern.
        for i in 0..4 {
            tracker.record(&event(BASE + i, "10.3.59.7", 37366), true);
        }

        let alerts = tracker.tick_at(&cfg, BASE + 60);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].urgency, "critical");
    }

    #[test]
    fn a_flow_that_stops_is_forgotten() {
        let cfg = Config::default();
        let mut tracker = SelfBlockTracker::new();

        for minute in 0..60 {
            tracker.record(&event(BASE + minute * 60, "224.0.0.252", 5355), false);
        }
        assert!(tracker.summary().is_some());

        // Well past the window with nothing new.
        assert!(
            tracker
                .tick_at(&cfg, BASE + 3600 + cfg.self_window_secs as i64 + 60)
                .is_empty()
        );
        assert!(tracker.summary().is_none());
    }
}

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
// That premise only holds for unicast traffic from somebody else, so `local`
// filters out the two classes of drop that cannot possibly mean it: packets
// this host sent itself, and packets addressed to a multicast or broadcast
// group. See that module for why both are false by construction.
//
// Reading the journal costs nothing and needs no privileges beyond membership
// in a group that can read kernel messages.
// =============================================================================

use std::{
    collections::{HashMap, VecDeque},
    io::{BufRead, BufReader},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc::{Receiver, channel},
    },
    thread,
    time::Duration,
};

use crate::{
    alert::{
        self, Alert, describe_source, describe_source_cached, device_label_cached, fmt_bytes,
        fmt_duration, identity, identity_cached, is_private, now_epoch, port_in_use,
    },
    config::{Config, DiscoveryReplies},
    discovery,
    local::{LocalNet, parse_ip},
    selfblock::SelfBlockTracker,
};

// -- Data Structures ----------------------------------------------------------

#[derive(Clone)]
pub struct BlockEvent {
    pub ts: i64,
    pub iface: String,
    pub src: String,
    pub dst: String,
    pub proto: String,
    pub sport: u16,
    pub dport: u16,
    /// IP total length, i.e. bytes on the wire for this packet.
    pub len: u64,
}

/// Why records were discarded before reaching the tracker.
///
/// Counted rather than logged per packet: a chatty segment produces thousands
/// of these an hour. Reported in `--replay` so a quiet result is visibly "these
/// were filtered", never a silent nothing.
#[derive(Default, Clone, Copy)]
pub struct SkipCounts {
    pub self_sourced: u64,
    pub group_dest: u64,
    pub ignored_port: u64,
    /// Answers to this host's own discovery, with `discovery_replies = ignore`
    /// in force. Under the default `quiet` these are not skipped at all — they
    /// are tracked and reported, just without a popup.
    pub discovery_reply: u64,
}

impl SkipCounts {
    pub fn total(&self) -> u64 {
        self.self_sourced + self.group_dest + self.ignored_port + self.discovery_reply
    }

    pub fn summary(&self) -> Option<String> {
        if self.total() == 0 {
            return None;
        }
        Some(format!(
            "{} record(s) ignored: {} sent by this host, {} addressed to a multicast \
             or broadcast group, {} on an ignored port, {} answering this host's own \
             discovery",
            self.total(),
            self.self_sourced,
            self.group_dest,
            self.ignored_port,
            self.discovery_reply,
        ))
    }
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
    /// Every distinct address this flow's packets were sent to, in arrival
    /// order. `FlowKey` carries no destination, and on a multi-homed host —
    /// this one included — a single flow genuinely lands on more than one
    /// local address. Corroboration has to hold for all of them: a binding on
    /// one address is no evidence about the packets sent to another, and
    /// checking only the latest would let the last packet vouch for every
    /// packet before it.
    dsts: Vec<String>,
    /// The flow used more destinations than any real multi-homed host has
    /// addresses. Refuses corroboration wholesale rather than letting a sender
    /// cycle destinations until the list stops being checked.
    dst_overflow: bool,
    alerted_at: Option<i64>,
    /// The discovery protocol every record in this flow has answered on.
    ///
    /// Sticky *off*: `FlowKey` does not include the source port, so one
    /// discovery-shaped packet can be followed by unrelated traffic from a
    /// different source port to the same destination. The moment any record
    /// disagrees, the flow stops being discovery for good, and cannot become it
    /// again. Failing this direction only ever means alerting.
    discovery: Option<&'static str>,
    /// Whether an alert for this flow was actually emitted. Distinct from
    /// `alerted_at`, which is also set when a round is suppressed by the shared
    /// cooldown — a flow that never announced itself must not announce that it
    /// has ended.
    announced: bool,
    /// What the flow was actually *reported* as, once it has announced. The
    /// wording when the flow ends has to match the wording when it started, or
    /// a discovery round that quietly explained itself signs off as a blocked
    /// flow.
    alerted_as_discovery: Option<&'static str>,
}

/// Distinct destination addresses a flow may accumulate before corroboration
/// is refused outright. Real multi-homed hosts have a handful of addresses;
/// a flow spraying more than this is not landing on one of them.
const MAX_FLOW_DSTS: usize = 8;

pub struct FlowTracker {
    flows: HashMap<FlowKey, FlowState>,
    local: LocalNet,
    skipped: SkipCounts,
    /// Records this detector rejects are not thrown away — traffic this host
    /// sends and then drops is a different problem, judged on its own terms.
    selfblock: SelfBlockTracker,
    /// Resolve names while building alerts, instead of emitting immediately
    /// and enriching in the background. Only `--replay` wants this: it is
    /// offline, blocking is free there, and it must never spawn threads that
    /// would raise real notifications about historical traffic.
    resolve_inline: bool,
    /// Enrichment waiting for its bare alert to be emitted first. Spawning at
    /// alert-build time raced the emit: a fast resolution could land the
    /// enriched popup first, only for the bare one to replace it through the
    /// same dedup key. The caller drains this *after* emitting.
    pending_enrich: Vec<(FlowFacts, Alert)>,
    /// When each (source, protocol) pair last raised a discovery alert.
    ///
    /// Cooldown cannot live on the flow here, the way it does for every other
    /// detector. Each discovery round asks from a *fresh* ephemeral port, so
    /// each round is a new `FlowKey` carrying `alerted_at: None` and clears the
    /// cooldown that was meant to hold it back. The subject that actually
    /// repeats is the device-and-protocol pair, so the cooldown has to be kept
    /// against that instead.
    ///
    /// Keyed on corroboration too. A corroborated round and an uncorroborated
    /// one are different findings with different urgencies, and sharing a
    /// cooldown between them would let the quiet one silence the loud one.
    discovery_alerted: HashMap<(String, &'static str, bool), i64>,
}

/// Everything an alert says about a flow, copied out of the tracker so a
/// background thread can rebuild the alert once names have resolved — the
/// tracker itself cannot cross a thread boundary, and should not.
#[derive(Clone)]
struct FlowFacts {
    src: String,
    proto_lower: String,
    dport: u16,
    sport: u16,
    total: u64,
    bytes: u64,
    iface: String,
    duration: String,
    listening: bool,
    /// Where the packets were most recently addressed — the address handed to
    /// process attribution, which needs one concrete address to match against.
    dst: String,
    /// A local socket is bound such that it could have received *every* packet
    /// in this flow, whichever local address each was sent to. Stronger than
    /// `listening`, which only asks whether the port is occupied anywhere — a
    /// loopback binding occupies a port without being able to receive a single
    /// LAN packet.
    corroborated: bool,
    nearby: bool,
    /// Name of the discovery protocol this flow is answering, when the record
    /// has that shape. Some(..) inverts the meaning of the whole alert: the
    /// source is replying to us, not transmitting at us.
    discovery: Option<&'static str>,
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
                Err(e) => eprintln!("packetminder: cannot run journalctl: {e}"),
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
    let dst = (*fields.get("DST")?).to_string();
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
        dst,
        proto,
        sport: fields.get("SPT").and_then(|v| v.parse().ok()).unwrap_or(0),
        dport: fields.get("DPT").and_then(|v| v.parse().ok()).unwrap_or(0),
        len: fields.get("LEN").and_then(|v| v.parse().ok()).unwrap_or(0),
    })
}

// -- Tracker ------------------------------------------------------------------

impl FlowTracker {
    pub fn new() -> Self {
        Self::with_local(LocalNet::detect(now_epoch()))
    }

    /// Build a tracker over a fixed view of this host's addresses. Used by
    /// tests, which must not depend on whatever the machine's real addresses
    /// happen to be.
    pub fn with_local(local: LocalNet) -> Self {
        Self {
            flows: HashMap::new(),
            local,
            skipped: SkipCounts::default(),
            selfblock: SelfBlockTracker::new(),
            resolve_inline: false,
            pending_enrich: Vec::new(),
            discovery_alerted: HashMap::new(),
        }
    }

    /// Resolve names while building alerts rather than in the background.
    /// `--replay` only: blocking is free offline, and replay must never spawn
    /// enrichment threads that raise real popups about historical traffic.
    pub fn resolve_names_inline(&mut self) {
        self.resolve_inline = true;
    }

    /// Start background enrichment for alerts the caller has now emitted.
    ///
    /// Separate from tick() on purpose: the enriched re-emit replaces the bare
    /// popup through the dedup key, and replacement only works if the bare one
    /// is on screen first. Spawning inside tick() raced that ordering.
    pub fn spawn_pending_enrichment(&mut self, cfg: &Config) {
        for (facts, bare) in self.pending_enrich.drain(..) {
            spawn_enrichment(cfg.clone(), facts, bare);
        }
    }

    pub fn skipped(&self) -> SkipCounts {
        self.skipped
    }

    /// What this host is currently having dropped by its own firewall, whether
    /// or not it has crossed the alerting threshold.
    pub fn selfblock_summary(&self) -> Option<String> {
        self.selfblock.summary()
    }

    /// Decide whether a drop record can possibly indicate misdirected traffic.
    ///
    /// The address set is re-read on a timer rather than per packet, so a DHCP
    /// renewal is picked up within a minute. `--replay` compares historical
    /// records against today's addresses, which is the best available answer:
    /// the journal does not record what this host's address was at the time.
    fn should_record(&mut self, event: &BlockEvent, cfg: &Config) -> bool {
        if cfg.ignore_ports.contains(&event.dport) {
            self.skipped.ignored_port += 1;
            return false;
        }

        self.local.refresh_if_stale(now_epoch());

        if let Some(src) = parse_ip(&event.src)
            && self.local.is_local(&src)
        {
            self.skipped.self_sourced += 1;
            // Nobody is transmitting at this host, so the flood detector must
            // not see it. That does not make it uninteresting. An unparseable
            // destination counts as a group, so garbage takes the quiet path.
            let unicast = parse_ip(&event.dst).is_some_and(|dst| !self.local.is_group(&dst));
            self.selfblock.record(event, unicast);
            return false;
        }

        if let Some(dst) = parse_ip(&event.dst)
            && self.local.is_group(&dst)
        {
            self.skipped.group_dest += 1;
            return false;
        }

        // Only `ignore` filters here. `quiet` deliberately lets the record
        // through: the flow is still tracked and still reported, because a
        // discovery reply being dropped is a true finding about this host's
        // firewall. It just does not get to raise a popup — that decision
        // belongs to the alert, not to the intake filter.
        if cfg.discovery_replies == DiscoveryReplies::Ignore
            && discovery::classify(
                &event.proto,
                event.sport,
                event.dport,
                is_nearby(&self.local, &event.src),
            )
            .is_some()
        {
            self.skipped.discovery_reply += 1;
            return false;
        }

        true
    }

    /// Fold a drop record into its flow. Returns false if it was filtered out.
    pub fn record(&mut self, event: BlockEvent, cfg: &Config) -> bool {
        if !self.should_record(&event, cfg) {
            return false;
        }

        let key = FlowKey {
            src: event.src.clone(),
            proto: event.proto.clone(),
            dport: event.dport,
        };

        let classified = discovery::classify(
            &event.proto,
            event.sport,
            event.dport,
            is_nearby(&self.local, &event.src),
        );

        let state = self.flows.entry(key).or_insert_with(|| FlowState {
            times: VecDeque::new(),
            total: 0,
            first: event.ts,
            last: event.ts,
            iface: event.iface.clone(),
            sport: event.sport,
            bytes: 0,
            dsts: vec![event.dst.clone()],
            dst_overflow: false,
            alerted_at: None,
            discovery: classified,
            announced: false,
            alerted_as_discovery: None,
        });

        // Any record that does not answer the same protocol as the ones before
        // it disqualifies the whole flow. A stream that is only sometimes
        // shaped like a reply is not a reply stream, and the source port it
        // arrived on is the sender's choice either way.
        if state.discovery != classified && state.discovery.is_some() {
            // Everything said about this flow was said about a different
            // thing, and the blocked flow it now is must be judged from
            // scratch. Above all the alert timestamp: inheriting it would let
            // a sender open with reply-shaped packets, take the quiet report,
            // and then flood for a whole cooldown without a popup.
            if state.announced {
                alert::log(&format!(
                    "discovery-revoked — {} → udp/{} stopped looking like {} replies; \
                     re-judging as a blocked flow",
                    device_label_cached(&event.src),
                    event.dport,
                    state.discovery.unwrap_or("discovery"),
                ));
            }
            state.discovery = None;
            state.alerted_at = None;
            state.announced = false;
            state.alerted_as_discovery = None;
        }

        if !state.dsts.contains(&event.dst) {
            if state.dsts.len() < MAX_FLOW_DSTS {
                state.dsts.push(event.dst.clone());
            } else {
                state.dst_overflow = true;
            }
        }

        state.times.push_back(event.ts);
        state.total += 1;
        state.bytes += event.len;
        state.last = event.ts;
        state.iface = event.iface;
        state.sport = event.sport;
        true
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
                    // `announced`, not `alerted_at`: the latter is also set for
                    // rounds the shared cooldown suppressed, and a flow that
                    // never spoke must not report having stopped.
                    if state.announced {
                        // Sign off the same way it was announced. A discovery
                        // round that explained itself on the way in must not
                        // sign off as a blocked flow on the way out.
                        let (kind, subject) = match state.alerted_as_discovery {
                            Some(protocol) => {
                                ("discovery-reply-ended", format!("{protocol} replies"))
                            }
                            None => (
                                "blocked-flow-ended",
                                format!("{}/{}", key.proto.to_lowercase(), key.dport),
                            ),
                        };
                        alert::log(&format!(
                            "{kind} — {} → {subject} stopped after {} ({} drops logged)",
                            device_label_cached(&key.src),
                            fmt_duration((state.last - state.first).max(0) as u64),
                            state.total,
                        ));
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

            // Corroboration has to be settled before the cooldown, not after.
            // The two tiers do not share a subject: a corroborated round is a
            // quiet standing fact, an uncorroborated one is supposed to
            // interrupt, and letting the first start a cooldown that swallows
            // the second would undo the whole point of separating them.
            let facts = gather_facts(key, state, now, &self.local);

            // A discovery flow's own cooldown is worthless, because the flow
            // itself is new every round. Hold it against the (device, protocol,
            // tier) subject, which is what a human would recognise as "this
            // again".
            if let Some(protocol) = state.discovery {
                let subject = (key.src.clone(), protocol, facts.corroborated);
                let repeat = self
                    .discovery_alerted
                    .get(&subject)
                    .is_some_and(|last| now - last < cfg.cooldown_secs as i64);
                if repeat {
                    // Mark the flow so a suppressed round does not re-evaluate
                    // on every subsequent tick — but leave `announced` alone.
                    // Nothing was said, so nothing may report having stopped.
                    state.alerted_at = Some(now);
                    continue;
                }
                self.discovery_alerted.insert(subject, now);
            }

            state.alerted_at = Some(now);
            state.announced = true;
            state.alerted_as_discovery = state.discovery;
            if self.resolve_inline {
                alerts.push(compose_alert(&facts, true, cfg));
            } else {
                // Emit with whatever the caches hold right now — the loop must
                // not wait on getent or whois. Enrichment is queued, not
                // spawned: it starts only once the caller has actually emitted
                // this alert, via spawn_pending_enrichment.
                let bare = compose_alert(&facts, false, cfg);
                self.pending_enrich.push((facts, bare.clone()));
                alerts.push(bare);
            }
        }

        for key in finished {
            self.flows.remove(&key);
        }

        // Cooldown entries outlive the flows they were recorded against, by
        // design — that is the point of keying on the device rather than the
        // port. Drop them once they can no longer suppress anything, so a
        // long-running daemon on a busy segment does not accumulate one entry
        // per device-protocol pair forever.
        let stale = cfg.cooldown_secs as i64;
        self.discovery_alerted
            .retain(|_, last| now - *last < stale);

        alerts.extend(self.selfblock.tick_at(cfg, now));
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
                    device_label_cached(&k.src),
                    k.proto.to_lowercase(),
                    k.dport,
                    s.times.len()
                )
            })
            .collect();

        Some(described.join("; "))
    }
}

/// Whether an address is something other than the internet.
///
/// Two conditions, and both are needed. On a subnet this host is attached to is
/// the only one that means anything under IPv6. Private v4 space is the
/// fallback: it still holds when address discovery has failed, and it covers a
/// LAN host reached through a router.
fn is_nearby(local: &LocalNet, src: &str) -> bool {
    parse_ip(src).is_some_and(|ip| local.is_on_link(&ip)) || is_private(src)
}

fn gather_facts(key: &FlowKey, state: &FlowState, now: i64, local: &LocalNet) -> FlowFacts {
    let nearby = is_nearby(local, &key.src);
    FlowFacts {
        src: key.src.clone(),
        proto_lower: key.proto.to_lowercase(),
        dport: key.dport,
        sport: state.sport,
        total: state.total,
        bytes: state.bytes,
        iface: state.iface.clone(),
        duration: fmt_duration((now - state.first).max(0) as u64),
        listening: port_in_use(&key.proto, key.dport),
        dst: state.dsts.last().cloned().unwrap_or_default(),
        // Only asked when it can change the answer. For a flow that is not
        // discovery-shaped at all, the /proc/net reads would be pure cost.
        // Every destination the flow touched has to be covered: on a
        // multi-homed host one flow lands on several local addresses, and the
        // last packet must not vouch for the ones before it.
        corroborated: state.discovery.is_some()
            && !state.dst_overflow
            && state.dsts.iter().all(|dst| {
                discovery::solicited_locally(&key.proto, &key.src, state.sport, dst, key.dport)
            }),
        nearby,
        // Sticky-off across the flow's life, not re-decided here.
        discovery: state.discovery,
    }
}

/// Build the alert from gathered facts. With `resolve` the lookups may wait on
/// the network; without it only caches are consulted, so it is safe on the
/// detector loop.
fn compose_alert(facts: &FlowFacts, resolve: bool, cfg: &Config) -> Alert {
    if let Some(protocol) = facts.discovery {
        return compose_discovery_alert(facts, protocol, resolve, cfg);
    }

    let proto = &facts.proto_lower;

    // Line one is what we worked out the device is; line two is what it did.
    // The raw hostname and address live in the title, because that is the half
    // you act on.
    let (who, derived) = if resolve {
        identity(&facts.src)
    } else {
        identity_cached(&facts.src)
    };

    let mut body = String::new();
    if let Some(d) = &derived {
        body.push_str(d);
        body.push('\n');
    }
    body.push_str(&format!(
        "{} drops over {} on {}, still going. {}",
        facts.total,
        facts.duration,
        facts.iface,
        if facts.listening {
            "Something IS listening — the firewall is blocking it."
        } else {
            "Nothing is listening."
        },
    ));

    // Everything below is true and occasionally useful, and none of it is worth
    // making the popup unreadable for.
    let mut detail = format!(
        "{} logged. ufw rate-limits its own logging, so the count measures \
         persistence, not volume.",
        fmt_bytes(facts.bytes),
    );
    if !facts.listening {
        detail.push_str(" The sender is getting no feedback because the drop is silent.");
    }
    let source = if resolve {
        describe_source(&facts.src, facts.nearby)
    } else {
        describe_source_cached(&facts.src, facts.nearby)
    };
    detail.push_str(&format!(" Source: {source}"));
    if facts.sport != 0 {
        detail.push_str(&format!(" from {proto}/{}", facts.sport));
    }

    // Volume cannot be read off a rate-limited log, so urgency comes from what
    // the situation means instead. A starved local service and a neighbour
    // transmitting into a black hole are both somebody's mistake worth waking
    // up for. The internet knocking on a closed port all day is just the
    // internet, and does not get to interrupt anyone.
    let urgency = if facts.listening || facts.nearby { "critical" } else { "normal" };

    Alert {
        kind: "blocked-flow",
        // Keyed on the address and never the resolved name, so that the popup
        // still replaces its predecessor when a name starts or stops resolving.
        key: format!("flow-{}-{}-{}", facts.src, proto, facts.dport),
        title: format!("{who} — blocked {proto}/{}", facts.dport),
        body,
        detail,
        urgency,
        popup: true,
    }
}

/// The same flow, told the right way round.
///
/// The blocked-flow wording accuses the source of transmitting into a host that
/// is not listening. Here the source answered a question this host asked, so
/// every part of that sentence is wrong, and the useful name is not the device
/// in the title but the local process holding the querying socket.
fn compose_discovery_alert(
    facts: &FlowFacts,
    protocol: &str,
    resolve: bool,
    cfg: &Config,
) -> Alert {
    let (who, derived) = if resolve {
        identity(&facts.src)
    } else {
        identity_cached(&facts.src)
    };

    // Reading /proc for the owning process is the same class of cost as getent
    // and whois, so it lives on the same side of the bare/enriched split and
    // never runs on the detector loop.
    let asker = if resolve {
        discovery::asker(&facts.proto_lower, &facts.src, facts.sport, &facts.dst, facts.dport)
    } else {
        None
    };

    let mut body = String::new();
    if let Some(d) = &derived {
        body.push_str(d);
        body.push('\n');
    }
    // A socket bound where the packet was addressed is the only evidence
    // available that this host actually asked. Source ports are chosen by the
    // sender, so without it the shape of a reply is a claim the sender made
    // about itself.
    if facts.corroborated {
        let asked = match &asker {
            Some(comm) => format!("{comm} asked"),
            // Bound but unattributable: another user owns it, or it closed
            // between the two lookups.
            None => "the asking socket is still open".to_string(),
        };
        body.push_str(&format!(
            "Answering this host's own {protocol} discovery — {asked}, and the firewall dropped \
             the reply. {} drops over {} on {}. Discovery is broken here, not an intrusion.",
            facts.total, facts.duration, facts.iface,
        ));
    } else {
        body.push_str(&format!(
            "Shaped like an answer to this host's own {protocol} discovery, but nothing that \
             could have received it is bound to {}/{} — a peer can send from {}/{} without being \
             asked anything. {} drops over {} on {}.",
            facts.proto_lower,
            facts.dport,
            facts.proto_lower,
            facts.sport,
            facts.total,
            facts.duration,
            facts.iface,
        ));
    }

    let mut detail = format!(
        "{} logged. The query went out to a multicast group and the answer came back unicast \
         from {}",
        fmt_bytes(facts.bytes),
        facts.src,
    );
    if facts.sport != 0 {
        detail.push_str(&format!(":{}", facts.sport));
    }
    detail.push_str(
        ", so conntrack has no entry to match it against and a default-deny input chain drops \
         it. To make discovery work, allow inbound udp from the local subnet; to make it stop, \
         turn discovery off in the program that asks.",
    );
    if !facts.corroborated {
        detail.push_str(&format!(
            " Reported at full urgency because it could not be corroborated: a source port is \
             chosen by the sender, so with no socket bound on an address that could have received \
             {} there is nothing to distinguish a late reply from a peer that simply sent from \
             that port. `discovery_replies = ignore` silences these too, at the cost of that \
             distinction.",
            facts.dst,
        ));
    }
    let source = if resolve {
        describe_source(&facts.src, facts.nearby)
    } else {
        describe_source_cached(&facts.src, facts.nearby)
    };
    detail.push_str(&format!(" Source: {source}"));

    Alert {
        kind: "discovery-reply",
        // Keyed on the protocol rather than the destination port, because the
        // port is a fresh ephemeral one every discovery round. Keying on it
        // made each round a brand-new subject, which is how one broken
        // discovery loop produced a stack of popups instead of one.
        key: format!("discovery-{}-{}", facts.src, protocol),
        title: if facts.corroborated {
            format!("{who} — {protocol} reply dropped")
        } else {
            format!("{who} — unsolicited {protocol} reply dropped")
        },
        body,
        detail,
        // Corroborated, this is a standing configuration fact about traffic
        // this host solicited: worth recording every time and worth
        // interrupting for approximately never.
        //
        // Uncorroborated, it is only the sender's word that this answers
        // anything. A dismissal nothing could substantiate does not earn
        // silence any more than an accusation nothing could substantiate earns
        // a critical popup — the same rule `asymmetric-inbound` applies to
        // itself, pointed the other way. `ignore` is how somebody opts out of
        // the distinction on purpose.
        urgency: if facts.corroborated { "low" } else { "normal" },
        popup: if facts.corroborated {
            cfg.discovery_replies == DiscoveryReplies::Alert
        } else {
            true
        },
    }
}

/// Enrichment threads in flight, and the most that may be. A port sweep can
/// push many distinct flows over the alert threshold in one tick; each would
/// otherwise spawn a thread that waits on getent and whois.
static ENRICHERS: AtomicUsize = AtomicUsize::new(0);
const MAX_ENRICHERS: usize = 8;

/// Frees the slot however the thread ends — a panicking lookup must not leak
/// capacity until nothing can ever enrich again.
struct EnricherSlot;

impl Drop for EnricherSlot {
    fn drop(&mut self) {
        ENRICHERS.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Resolve names off the loop, then re-emit if resolution changed anything.
///
/// The re-emit reuses the alert's dedup key, so the popup on screen updates in
/// place rather than stacking; the journal gets a second, richer line. When
/// the caches already held everything — the common case for a repeat offender
/// — the rebuilt alert is identical and nothing is emitted at all.
///
/// Bounded: past MAX_ENRICHERS concurrent workers the enrichment is skipped,
/// not queued. The immediate alert was already complete when it was emitted;
/// enrichment is a refinement, and refinements do not get to exhaust threads.
fn spawn_enrichment(cfg: Config, facts: FlowFacts, bare: Alert) {
    if ENRICHERS.fetch_add(1, Ordering::SeqCst) >= MAX_ENRICHERS {
        ENRICHERS.fetch_sub(1, Ordering::SeqCst);
        return;
    }
    thread::spawn(move || {
        let _slot = EnricherSlot;
        let enriched = compose_alert(&facts, true, &cfg);
        if enriched.title != bare.title
            || enriched.body != bare.body
            || enriched.detail != bare.detail
        {
            let _ = alert::emit(&cfg, &enriched);
        }
    });
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

    /// The real thing: a Sunshine host streaming into a port nothing was bound
    /// to. Unicast, from a neighbour, addressed to this host.
    const SAMPLE: &str = "2026-08-03T00:50:53-07:00 ithilien kernel: [UFW BLOCK] IN=wlp1s0 OUT= \
        MAC=3c:3b:ad:16:b7:30:18:db:f2:4d:bb:ee:08:00 SRC=10.3.59.7 DST=10.3.153.246 LEN=1436 \
        TOS=0x00 PREC=0xA0 TTL=128 ID=40959 PROTO=UDP SPT=47998 DPT=37366 LEN=1416";

    /// The false positive the filter exists for: systemd-resolved's own LLMNR
    /// query, looped back into INPUT by the kernel and dropped by a default-deny
    /// firewall. SRC is this host and MAC= is empty, because the packet never
    /// reached the wire.
    const OWN_LOOPBACK: &str = "2026-08-03T10:35:02-07:00 ithilien kernel: [UFW BLOCK] \
        IN=wlp1s0 OUT= MAC= SRC=10.3.153.246 DST=224.0.0.252 LEN=54 TOS=0x00 PREC=0x00 TTL=255 \
        ID=10390 PROTO=UDP SPT=5355 DPT=5355 LEN=34";

    /// A neighbour's LLMNR query: genuinely from somebody else, but addressed to
    /// the whole segment rather than to this host.
    const NEIGHBOUR_MULTICAST: &str = "2026-08-03T10:12:52-07:00 ithilien kernel: [UFW BLOCK] \
        IN=wlp1s0 OUT= MAC= SRC=fe80:0000:0000:0000:b787:4f5d:1cbb:eb39 \
        DST=ff02:0000:0000:0000:0000:0000:0001:0003 LEN=74 TC=0 HOPLIMIT=255 FLOWLBL=258456 \
        PROTO=UDP SPT=5355 DPT=5355 LEN=34";

    /// The false positive this reads backwards: a Roku answering an SSDP
    /// M-SEARCH that this host multicast. Unicast from a neighbour, addressed
    /// to this host, sustained — indistinguishable from SAMPLE except that the
    /// source port says it is a reply.
    ///
    /// Parameterised by destination port because corroboration now depends on
    /// whether a socket is bound to it, and a test that hard-coded a port would
    /// pass or fail on whatever the host running it happens to have open.
    fn ssdp_reply(dport: u16) -> String {
        ssdp_reply_to("10.3.153.246", dport)
    }

    /// The same reply aimed at a chosen local address, for the multi-homed
    /// cases where the destination is the variable under test.
    fn ssdp_reply_to(dst: &str, dport: u16) -> String {
        format!(
            "2026-08-28T00:42:04-07:00 ithilien kernel: [UFW BLOCK] IN=wlp1s0 OUT= \
             MAC=3c:3b:ad:16:b7:30:a8:b5:7c:53:b2:fe:08:00 SRC=10.3.193.195 \
             DST={dst} LEN=328 TOS=0x00 PREC=0x00 TTL=64 ID=46308 DF PROTO=UDP \
             SPT=1900 DPT={dport} LEN=308"
        )
    }

    /// The same record with an arbitrary source port, for the cases where the
    /// source port is the variable under test.
    fn reply_from(sport: u16, dport: u16) -> String {
        format!(
            "2026-08-28T00:42:04-07:00 ithilien kernel: [UFW BLOCK] IN=wlp1s0 OUT= \
             MAC=3c:3b:ad:16:b7:30:a8:b5:7c:53:b2:fe:08:00 SRC=10.3.193.195 \
             DST=10.3.153.246 LEN=328 TOS=0x00 PREC=0x00 TTL=64 ID=46308 DF PROTO=UDP \
             SPT={sport} DPT={dport} LEN=308"
        )
    }

    /// A wildcard-bound UDP socket, which is what a real discovery client holds
    /// and what can legitimately corroborate LAN-addressed traffic. Returned so
    /// the caller keeps it alive — dropping it changes the classification.
    fn bound_socket() -> (std::net::UdpSocket, u16) {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind an ephemeral port");
        let port = socket.local_addr().expect("local addr").port();
        (socket, port)
    }

    /// Distinct ports inside the kernel's real ephemeral range with nothing
    /// bound to them — the shape of a reply whose querying socket has closed.
    ///
    /// Asking the kernel and releasing is the only honest source: the range is
    /// host configuration, so a hard-coded number lands outside it somewhere.
    /// Binding all `n` first guarantees distinctness; the check afterwards
    /// catches the slim race of another process claiming one in between.
    fn unbound_ports<const N: usize>() -> [u16; N] {
        for _ in 0..16 {
            let sockets: Vec<std::net::UdpSocket> = (0..N)
                .map(|_| std::net::UdpSocket::bind("0.0.0.0:0").expect("bind"))
                .collect();
            let mut ports = [0u16; N];
            for (slot, socket) in ports.iter_mut().zip(&sockets) {
                *slot = socket.local_addr().expect("local addr").port();
            }
            drop(sockets);
            if ports.iter().all(|&p| !port_in_use("UDP", p)) {
                return ports;
            }
        }
        panic!("could not find {N} unbound ephemeral ports");
    }

    /// Feed a record in often enough and long enough to clear both thresholds.
    fn sustain(tracker: &mut FlowTracker, cfg: &Config, record: &str, base: i64) -> Vec<Alert> {
        for i in 0..6 {
            let mut event = parse_line(record).expect("should parse");
            event.ts = base + i * 40;
            tracker.record(event, cfg);
        }
        tracker.tick_at(cfg, base + 200)
    }

    /// Capture what a flow logs when it ends, by running the tracker past the
    /// window and reading back the classification it signed off with.
    fn ended_as_discovery(tracker: &FlowTracker, src: &str, dport: u16) -> Option<&'static str> {
        tracker
            .flows
            .get(&FlowKey {
                src: src.to_string(),
                proto: "UDP".to_string(),
                dport,
            })
            .and_then(|state| state.alerted_as_discovery)
    }

    /// A tracker that believes it owns this machine's addresses, so tests never
    /// depend on whatever the host running them actually has configured.
    ///
    /// Inline resolution, for the same reason --replay uses it: the background
    /// path spawns threads that end in notify-send, and a test suite that
    /// raises desktop popups has failed at being a test suite.
    fn tracker() -> FlowTracker {
        let mut t =
            FlowTracker::with_local(LocalNet::from_parts(&["10.3.153.246/16"], &["10.3.255.255"]));
        t.resolve_names_inline();
        t
    }

    #[test]
    fn parses_a_real_drop_record() {
        let event = parse_line(SAMPLE).expect("should parse");
        assert_eq!(event.src, "10.3.59.7");
        assert_eq!(event.dst, "10.3.153.246");
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
        let base = 1_785_743_453;

        let mut sustained = tracker();
        for i in 0..6 {
            let mut event = parse_line(SAMPLE).expect("should parse");
            event.ts = base + i * 40;
            assert!(sustained.record(event, &cfg));
        }
        assert_eq!(sustained.tick_at(&cfg, base + 200).len(), 1);

        let mut brief = tracker();
        for i in 0..3 {
            let mut event = parse_line(SAMPLE).expect("should parse");
            event.ts = base + i;
            event.src = "10.3.59.8".into();
            assert!(brief.record(event, &cfg));
        }
        assert!(brief.tick_at(&cfg, base + 3).is_empty());
    }

    #[test]
    fn never_alerts_on_this_hosts_own_loopback_multicast() {
        let cfg = Config::default();
        let base = 1_785_777_302;
        let mut tracker = tracker();

        // Well past both thresholds: only the filter can keep this quiet.
        for i in 0..20 {
            let mut event = parse_line(OWN_LOOPBACK).expect("should parse");
            event.ts = base + i * 30;
            assert!(!tracker.record(event, &cfg), "self-sourced must not record");
        }

        assert!(tracker.tick_at(&cfg, base + 600).is_empty());
        assert_eq!(tracker.skipped().self_sourced, 20);
    }

    #[test]
    fn never_alerts_on_traffic_addressed_to_a_group() {
        let cfg = Config::default();
        let base = 1_785_773_572;
        let mut tracker = tracker();

        for i in 0..20 {
            let mut event = parse_line(NEIGHBOUR_MULTICAST).expect("should parse");
            event.ts = base + i * 30;
            assert!(!tracker.record(event, &cfg), "multicast must not record");
        }

        assert!(tracker.tick_at(&cfg, base + 600).is_empty());
        // Source is a neighbour, so this can only have been caught by the
        // destination check — the expanded IPv6 form and all.
        assert_eq!(tracker.skipped().group_dest, 20);
    }

    #[test]
    fn subnet_broadcast_counts_as_a_group_address() {
        let cfg = Config::default();
        let mut tracker = tracker();

        let mut event = parse_line(SAMPLE).expect("should parse");
        event.dst = "10.3.255.255".into();
        assert!(!tracker.record(event, &cfg));
        assert_eq!(tracker.skipped().group_dest, 1);
    }

    #[test]
    fn a_corroborated_reply_to_our_own_discovery_never_pops_up() {
        // Hold the socket open for the duration: it is the evidence that this
        // host asked, and dropping it would change the classification.
        let (_socket, port) = bound_socket();

        let cfg = Config::default();
        let mut tracker = tracker();
        let alerts = sustain(&mut tracker, &cfg, &ssdp_reply(port), 1_787_000_000);

        assert_eq!(alerts.len(), 1, "the flow is still reported");
        let a = &alerts[0];
        assert_eq!(a.kind, "discovery-reply", "not a flood, and must not say so");
        assert!(!a.popup, "quiet is the default when corroborated: journal only");
        assert_eq!(a.urgency, "low");
        assert!(a.body.contains("SSDP"), "the protocol has to be named: {}", a.body);
        assert!(
            !a.body.contains("Nothing is listening"),
            "the blocked-flow wording must not leak into this: {}",
            a.body
        );
        // Keyed on the protocol, not the ephemeral port, so the next discovery
        // round replaces this rather than stacking beside it.
        assert_eq!(a.key, "discovery-10.3.193.195-SSDP");
    }

    #[test]
    fn an_uncorroborated_reply_is_explained_but_still_interrupts() {
        // Nothing is bound to the port being "answered", so only the sender's
        // choice of source port says this replies to anything. A peer on the
        // LAN can make that claim without this host having asked, so it keeps
        // its popup — the finding is explained, not dismissed.
        let [port] = unbound_ports();
        let cfg = Config::default();
        let mut tracker = tracker();
        let alerts = sustain(&mut tracker, &cfg, &ssdp_reply(port), 1_787_000_000);

        assert_eq!(alerts.len(), 1);
        let a = &alerts[0];
        assert_eq!(a.kind, "discovery-reply");
        assert!(a.popup, "an uncorroborated dismissal does not earn silence");
        assert_eq!(a.urgency, "normal");
        assert!(
            a.title.contains("unsolicited"),
            "the title must not claim we asked: {}",
            a.title
        );
    }

    #[test]
    fn discovery_replies_can_be_asked_for_or_filtered_outright() {
        let base = 1_787_000_000;
        let (_socket, port) = bound_socket();

        let alert_cfg = Config {
            discovery_replies: DiscoveryReplies::Alert,
            ..Config::default()
        };
        let mut asked_for = tracker();
        let alerts = sustain(&mut asked_for, &alert_cfg, &ssdp_reply(port), base);
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].popup, "`alert` opts back in to the popup");
        assert_eq!(alerts[0].urgency, "low", "explained and benign, even when shown");

        // `ignore` filters at intake, so it does not depend on corroboration.
        let ignore_cfg = Config {
            discovery_replies: DiscoveryReplies::Ignore,
            ..Config::default()
        };
        let [unbound] = unbound_ports();
        let mut filtered = tracker();
        for i in 0..6 {
            let mut event = parse_line(&ssdp_reply(unbound)).expect("should parse");
            event.ts = base + i * 40;
            assert!(!filtered.record(event, &ignore_cfg), "must not reach the tracker");
        }
        assert!(filtered.tick_at(&ignore_cfg, base + 200).is_empty());
        assert_eq!(filtered.skipped().discovery_reply, 6);
    }

    #[test]
    fn a_new_round_on_a_new_port_is_held_by_the_cooldown() {
        // The bug this guards: every discovery round asks from a fresh
        // ephemeral port, so every round was a new FlowKey carrying
        // `alerted_at: None` and cleared the per-flow cooldown. Two rounds on
        // two ports, well inside the cooldown, must produce one alert.
        let [round1, round2, round3] = unbound_ports();
        let cfg = Config::default();
        let mut tracker = tracker();
        let base = 1_787_000_000;

        let first = sustain(&mut tracker, &cfg, &ssdp_reply(round1), base);
        assert_eq!(first.len(), 1, "the first round is reported");

        let second = sustain(&mut tracker, &cfg, &ssdp_reply(round2), base + 300);
        assert!(
            second.is_empty(),
            "a second round inside the cooldown must not alert again: {:?}",
            second.iter().map(|a| &a.title).collect::<Vec<_>>()
        );

        // Past the cooldown the subject is allowed to speak up again.
        let later = base + cfg.cooldown_secs as i64 + 1000;
        let third = sustain(&mut tracker, &cfg, &ssdp_reply(round3), later);
        assert_eq!(third.len(), 1, "past the cooldown it reports again");
    }

    #[test]
    fn corroboration_must_cover_every_address_the_flow_was_sent_to() {
        use std::net::UdpSocket;

        // A socket bound to one specific address, and a flow that lands on it
        // AND on an address the socket cannot receive. FlowKey carries no
        // destination, so both land in the same flow — and the covered half
        // must not vouch for the uncovered half.
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind loopback");
        let port = socket.local_addr().expect("local addr").port();

        let cfg = Config::default();
        let mut split = tracker();
        let base = 1_787_000_000;
        for i in 0..6 {
            let dst = if i % 2 == 0 { "127.0.0.1" } else { "10.3.153.246" };
            let mut event = parse_line(&ssdp_reply_to(dst, port)).expect("should parse");
            event.ts = base + i * 40;
            split.record(event, &cfg);
        }
        let alerts = split.tick_at(&cfg, base + 200);
        assert_eq!(alerts.len(), 1);
        assert!(
            alerts[0].popup,
            "half-covered is uncorroborated: the last packet must not vouch for the rest"
        );
        assert!(alerts[0].title.contains("unsolicited"));

        // The same split flow against a wildcard binding is fully covered.
        drop(socket);
        let (_wildcard, wide_port) = bound_socket();
        let mut covered = tracker();
        for i in 0..6 {
            let dst = if i % 2 == 0 { "127.0.0.1" } else { "10.3.153.246" };
            let mut event = parse_line(&ssdp_reply_to(dst, wide_port)).expect("should parse");
            event.ts = base + i * 40;
            covered.record(event, &cfg);
        }
        let alerts = covered.tick_at(&cfg, base + 200);
        assert_eq!(alerts.len(), 1);
        assert!(
            !alerts[0].popup,
            "a wildcard covers every local address, so the split flow is corroborated"
        );
    }

    #[test]
    fn a_quiet_round_cannot_silence_an_uncorroborated_one() {
        // The cooldown used to be consulted before corroboration was known, so
        // a corroborated quiet round started a cooldown that then swallowed an
        // uncorroborated round — which is precisely the one that must
        // interrupt. The two tiers get separate cooldown subjects.
        let cfg = Config::default();
        let mut tracker = tracker();
        let base = 1_787_000_000;
        let (_socket, port) = bound_socket();

        let quiet = sustain(&mut tracker, &cfg, &ssdp_reply(port), base);
        assert_eq!(quiet.len(), 1);
        assert!(!quiet[0].popup, "the corroborated round is quiet");

        // Same source, same protocol, well inside the cooldown the quiet round
        // just started — but nothing is bound to this port.
        let [unbound] = unbound_ports();
        let loud = sustain(&mut tracker, &cfg, &ssdp_reply(unbound), base + 60);
        assert_eq!(loud.len(), 1, "the uncorroborated round must still be raised");
        assert!(loud[0].popup, "and must still interrupt");
        assert!(loud[0].title.contains("unsolicited"));
    }

    #[test]
    fn a_round_suppressed_by_the_cooldown_never_reports_stopping() {
        // The suppression branch sets `alerted_at` for bookkeeping. If the
        // ended-log keyed on that, a round that was never announced would
        // announce that it had stopped.
        let [round1, round2] = unbound_ports();
        let cfg = Config::default();
        let mut tracker = tracker();
        let base = 1_787_000_000;

        sustain(&mut tracker, &cfg, &ssdp_reply(round1), base);
        let second = sustain(&mut tracker, &cfg, &ssdp_reply(round2), base + 60);
        assert!(second.is_empty(), "second round inside the cooldown is suppressed");

        let suppressed = tracker
            .flows
            .get(&FlowKey {
                src: "10.3.193.195".to_string(),
                proto: "UDP".to_string(),
                dport: round2,
            })
            .expect("the suppressed flow is still tracked");
        assert!(suppressed.alerted_at.is_some(), "bookkeeping still happened");
        assert!(
            !suppressed.announced,
            "but nothing was said, so nothing may report having stopped"
        );
    }

    #[test]
    fn a_flow_whose_source_port_changes_is_no_longer_discovery() {
        // FlowKey does not include the source port, so one discovery-shaped
        // packet can be followed by unrelated traffic to the same destination
        // port. Classification is sticky-off: the moment a record disagrees,
        // the flow stops being discovery and cannot become it again.
        let cfg = Config::default();
        let mut tracker = tracker();
        let base = 1_787_000_000;
        let (_socket, port) = bound_socket();

        // One reply-shaped packet, then sustained traffic from an ordinary
        // source port to the same destination.
        let mut opener = parse_line(&ssdp_reply(port)).expect("should parse");
        opener.ts = base;
        tracker.record(opener, &cfg);
        for i in 1..6 {
            let mut event = parse_line(&reply_from(40000, port)).expect("should parse");
            event.ts = base + i * 40;
            tracker.record(event, &cfg);
        }

        let alerts = tracker.tick_at(&cfg, base + 200);
        assert_eq!(alerts.len(), 1);
        assert_eq!(
            alerts[0].kind, "blocked-flow",
            "a stream that is only sometimes reply-shaped is not a reply stream"
        );
        assert!(alerts[0].popup, "and it keeps its popup even with a socket bound");
    }

    #[test]
    fn a_revoked_flow_does_not_inherit_the_discovery_cooldown() {
        // The opening a sender could otherwise buy: fire reply-shaped packets
        // until the discovery report stamps the flow's alert timestamp, then
        // flood the same destination port. Sticky-off reclassifies the flow,
        // but without a reset the per-flow cooldown would swallow the
        // blocked-flow alert for half an hour.
        let [port] = unbound_ports();
        let cfg = Config::default();
        let mut tracker = tracker();
        let base = 1_787_000_000;

        let opening = sustain(&mut tracker, &cfg, &ssdp_reply(port), base);
        assert_eq!(opening.len(), 1);
        assert_eq!(opening[0].kind, "discovery-reply", "the bait round is reported");

        // The flood arrives on the same flow, well inside the cooldown the
        // discovery report started.
        let flood_start = base + 300;
        for i in 0..6 {
            let mut event = parse_line(&reply_from(40000, port)).expect("should parse");
            event.ts = flood_start + i * 40;
            tracker.record(event, &cfg);
        }
        let alerts = tracker.tick_at(&cfg, flood_start + 200);
        assert_eq!(alerts.len(), 1, "the reclassified flood must alert immediately");
        assert_eq!(alerts[0].kind, "blocked-flow");
        assert!(alerts[0].popup, "and it interrupts — no inherited quiet");
        assert_eq!(
            ended_as_discovery(&tracker, "10.3.193.195", port),
            None,
            "and it will sign off as what it became, not what it opened as"
        );
    }

    #[test]
    fn a_flow_signs_off_the_way_it_was_announced() {
        // The bug this guards: the cleanup path logged `blocked-flow-ended`
        // for every flow, so a discovery round that had explained itself on
        // the way in was reported as a blocked flow on the way out.
        let cfg = Config::default();
        let base = 1_787_000_000;

        let [unbound] = unbound_ports();
        let mut discovery_flow = tracker();
        sustain(&mut discovery_flow, &cfg, &ssdp_reply(unbound), base);
        assert_eq!(
            ended_as_discovery(&discovery_flow, "10.3.193.195", unbound),
            Some("SSDP"),
            "a reported discovery flow must remember that is what it was"
        );

        let mut flood = tracker();
        sustain(&mut flood, &cfg, SAMPLE, base);
        assert_eq!(
            ended_as_discovery(&flood, "10.3.59.7", 37366),
            None,
            "a flood must not sign off as discovery"
        );
    }

    #[test]
    fn a_real_flood_is_untouched_by_the_discovery_rule() {
        // The Sunshine stream this daemon was written for. Same shape, same
        // neighbour, same sustained unicast — and its source port is not a
        // discovery port, so none of the above may apply to it.
        let cfg = Config::default();
        let mut tracker = tracker();
        let alerts = sustain(&mut tracker, &cfg, SAMPLE, 1_785_743_453);

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, "blocked-flow");
        assert!(alerts[0].popup, "a real flood still interrupts");
        assert_eq!(alerts[0].urgency, "critical");
    }

    #[test]
    fn ignore_ports_drops_records_before_anything_else() {
        let cfg = Config {
            ignore_ports: vec![37366],
            ..Config::default()
        };
        let mut tracker = tracker();

        let event = parse_line(SAMPLE).expect("should parse");
        assert!(!tracker.record(event, &cfg));
        assert_eq!(tracker.skipped().ignored_port, 1);
    }
}

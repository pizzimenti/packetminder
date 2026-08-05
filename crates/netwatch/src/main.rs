// =============================================================================
// netwatch — background detector for inbound traffic nothing consumes.
//
// netwatch's TUI and GUI answer "what are my connections doing?" by polling
// `ss`. That is connection-oriented by construction, so it is blind to traffic
// that never forms a connection: UDP aimed at a port with no socket has no row
// in `ss`, no conntrack entry, and no owning process — yet it still saturates a
// link. This daemon watches the two places such traffic *is* visible:
//
//   asymmetry     /proc/net/dev counters. Inbound with no matching outbound
//                 means this host is not part of the conversation.
//   blocked flows the kernel log. Repeated firewall drops from one source name
//                 the culprit exactly.
//
// Written after a Sunshine host streamed 2.7 Mbps of video at this machine for
// an unknown length of time, into a port nothing was listening on, while every
// existing tool showed an idle network.
// =============================================================================

mod alert;
mod collector;
mod config;
mod flows;
mod iface;
mod local;
mod proto;
mod role;
mod selfblock;
mod sockets;

use std::{
    collections::HashSet, env, net::IpAddr, process::Command, thread,
    time::Duration,
};

use crate::{
    alert::Alert,
    config::Config,
    flows::FlowTracker,
    iface::AsymDetector,
};

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let cfg = Config::load();

    // Every subcommand labels devices, so this has to happen before any of
    // them run -- not just before the monitoring loop.
    alert::set_names(cfg.names.clone());

    match args.first().map(String::as_str) {
        None => run(cfg),
        Some("--replay") => replay(cfg, args.get(1).map(String::as_str).unwrap_or("-24h")),
        Some("--status") => status(cfg),
        Some("--selftest") => selftest(cfg),
        Some("--help" | "-h") => usage(),
        Some(other) => {
            eprintln!("netwatch: unknown argument `{other}`");
            usage();
            std::process::exit(2);
        }
    }
}

fn usage() {
    println!(
        "Usage: netwatch [option]

Run with no arguments to start monitoring (this is what the service does).

  --replay [SINCE]  Report what would have alerted over past journal history.
                    SINCE is any journalctl time spec; defaults to -24h.
  --status          Print one interface sample and exit.
  --selftest        Emit a test alert through the real notification path.
  --help            Show this message.

Config: {}",
        config::config_path().display()
    );
}

// -- Main Loop ----------------------------------------------------------------

/// How often the event log records what this host is having dropped, whether or
/// not it is anywhere near alerting.
const SELF_SUMMARY_SECS: i64 = 3600;

/// How often the set of assigned IPv6 addresses is re-read.
const IPV6_CHECK_SECS: i64 = 60;

fn run(cfg: Config) {
    alert::log(&format!("started — {}", cfg.summary()));
    // What this host *is* determines how its traffic should be read, so record
    // it once at startup. Changes are picked up per tick, not from this line.
    alert::log(&format!("role — {}", role::describe()));

    let events = flows::spawn_follower(&cfg.block_pattern);
    let mut asym = AsymDetector::new();
    let mut tracker = FlowTracker::new();
    let mut counters = proto::ProtoDetector::new();
    let mut last_self_summary = alert::now_epoch();

    // Seed the IPv6 set rather than treating whatever is already assigned as
    // having just appeared, which would fire on every restart. Startup state
    // goes to the log instead, where it is a fact rather than an interruption.
    let mut ipv6_seen = local::ipv6_addrs();
    let mut last_ipv6_check = alert::now_epoch();
    if cfg.watch_ipv6 {
        alert::log(&format!("ipv6 at startup — {}", describe_ipv6(&ipv6_seen)));
    }

    loop {
        // Drain everything the follower has seen since the last tick.
        while let Ok(event) = events.try_recv() {
            tracker.record(event, &cfg);
        }

        for a in tracker.tick(&cfg) {
            alert::emit(&cfg, &a);
        }

        // An interface-level alert is far more useful when it can name the
        // source, so hand it whatever the drop log currently knows.
        let hint = tracker.recent_summary(3);
        for a in asym.tick(&cfg, hint) {
            alert::emit(&cfg, &a);
        }

        // Kernel counters. These see two things nothing else here can: traffic
        // the firewall lets through to a dead port, and traffic this host
        // wanted but could not drain fast enough.
        if cfg.watch_proto {
            for a in counters.tick(&cfg) {
                alert::emit(&cfg, &a);
            }
        }

        // Record this host's own blocked traffic periodically even when it is
        // nowhere near the alert threshold. It is still consuming the ufw log
        // budget, and a line in the event log is what keeps that recoverable
        // rather than merely filtered away.
        let now = alert::now_epoch();
        if now - last_self_summary >= SELF_SUMMARY_SECS {
            last_self_summary = now;
            if let Some(summary) = tracker.selfblock_summary() {
                alert::log(&format!("self-blocked — {summary}"));
            }
        }

        if cfg.watch_ipv6 && now - last_ipv6_check >= IPV6_CHECK_SECS {
            last_ipv6_check = now;
            if let Some(a) = check_ipv6(&mut ipv6_seen) {
                alert::emit(&cfg, &a);
            }
        }

        thread::sleep(Duration::from_secs(cfg.interval_secs));
    }
}

// -- IPv6 Watch ---------------------------------------------------------------

fn describe_ipv6(addrs: &HashSet<IpAddr>) -> String {
    if addrs.is_empty() {
        return "none assigned".to_string();
    }
    let mut listed: Vec<String> = addrs.iter().map(IpAddr::to_string).collect();
    listed.sort();
    listed.join(", ")
}

/// Report IPv6 addresses that were not there last time, updating `seen`.
///
/// Only appearances are reported. Addresses going away is the interface being
/// reconfigured or unplugged, which happens constantly on a machine that roams
/// and says nothing about whether IPv6 is enabled.
fn check_ipv6(seen: &mut HashSet<IpAddr>) -> Option<Alert> {
    let current = local::ipv6_addrs();
    let mut appeared: Vec<String> = current.difference(seen).map(IpAddr::to_string).collect();
    *seen = current;

    if appeared.is_empty() {
        return None;
    }
    appeared.sort();

    Some(Alert {
        kind: "ipv6-active",
        key: "ipv6-active".to_string(),
        title: "IPv6 addressing became active".to_string(),
        body: format!(
            "New address(es): {}.\n\
             Something enabled IPv6 on an interface that did not have it.",
            appeared.join(", ")
        ),
        detail: "Where IPv6 is meant to stay off, the usual cause is NetworkManager rather \
                 than the kernel: a profile with ipv6.method=auto clears disable_ipv6 for its \
                 own interface, which overrides anything set in /etc/sysctl.d."
            .to_string(),
        urgency: "normal",
    })
}

// -- Replay -------------------------------------------------------------------

/// Re-run the blocked-flow detector over journal history.
///
/// This is the honest way to tune thresholds: point it at a period when
/// something was actually wrong and confirm it fires, then point it at a
/// normal day and confirm it stays quiet.
fn replay(cfg: Config, since: &str) {
    // Replay is read-only by construction now that findings only go to stderr.
    // It used to need log_path pointed at /dev/null, because otherwise it
    // appended its findings to the event log stamped with today's time and
    // corrupted the very history it exists to examine.
    println!("Replaying kernel drops since {since} with: {}\n", cfg.summary());

    let output = Command::new("journalctl")
        .args([
            "-k",
            "--since",
            since,
            "-o",
            "short-iso",
            "--no-pager",
            "--grep",
            &cfg.block_pattern,
        ])
        .output();

    let output = match output {
        Ok(o) => o,
        Err(e) => {
            eprintln!("cannot run journalctl: {e}");
            std::process::exit(1);
        }
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut events: Vec<flows::BlockEvent> =
        text.lines().filter_map(flows::parse_line).collect();
    events.sort_by_key(|e| e.ts);

    if events.is_empty() {
        println!("No matching drop records in that period.");
        return;
    }

    let first = events.first().map(|e| e.ts).unwrap_or(0);
    let last = events.last().map(|e| e.ts).unwrap_or(0);
    println!(
        "{} drop records from {} to {}\n",
        events.len(),
        alert::fmt_iso_local(first),
        alert::fmt_iso_local(last),
    );

    // Feed events through the tracker at their original timestamps.
    let mut tracker = FlowTracker::new();
    let mut alerts: Vec<(i64, Alert)> = Vec::new();
    for event in events {
        let ts = event.ts;
        tracker.record(event, &cfg);
        for a in tracker.tick_at(&cfg, ts) {
            alerts.push((ts, a));
        }
    }
    // Final sweep so flows that ended are reported as ended.
    for a in tracker.tick_at(&cfg, last + cfg.block_window_secs as i64 + 1) {
        alerts.push((last, a));
    }

    // Say what was filtered out. A quiet replay should be readable as "these
    // were discarded on purpose", never as an unexplained absence of results.
    if let Some(skipped) = tracker.skipped().summary() {
        println!("{skipped}\n");
    }

    if alerts.is_empty() {
        println!("Nothing would have alerted.");
        return;
    }

    println!("Would have raised {} alert(s):\n", alerts.len());
    for (ts, a) in alerts {
        println!("  {} [{}] {}", alert::fmt_iso_local(ts), a.kind, a.title);
        for line in a.body.lines() {
            println!("      {line}");
        }
        println!();
    }
}

// -- One-shot Modes -----------------------------------------------------------

fn status(cfg: Config) {
    // Taken before the sampling sleep so the drop figure below covers the same
    // window as the interface rates.
    let snapshot_before = collector::read();

    let mut detector = AsymDetector::new();
    thread::sleep(Duration::from_secs(cfg.interval_secs.clamp(2, 5)));
    detector.tick(&cfg, None);

    println!("{}", cfg.summary());
    println!("role: {}\n", role::describe());

    let routing = role::is_forwarding();
    let host_tx_bps: f64 = detector.rates.values().map(|r| r.tx_bps).sum();

    let mut names: Vec<&String> = detector.rates.keys().collect();
    names.sort();

    for name in names {
        let r = &detector.rates[name];
        let ratio = if r.rx_bps > 0.0 {
            r.tx_bps / r.rx_bps * 100.0
        } else {
            0.0
        };
        // Mirror the detector exactly, forwarding included, or --status would
        // disagree with the alerts it exists to explain.
        let answering = if routing { host_tx_bps } else { r.tx_bps };
        let flag = if r.rx_bps >= cfg.rx_floor_bps && answering < r.rx_bps * cfg.asym_ratio {
            "  <-- one-sided"
        } else {
            ""
        };
        println!(
            "{name:14} rx {:>12}  tx {:>12}  ({ratio:.1}% out){flag}",
            alert::fmt_bits(r.rx_bps),
            alert::fmt_bits(r.tx_bps),
        );
    }

    // The question a one-sided reading actually raises: is anything reading it?
    if cfg.socket_corroboration {
        let total_rx: f64 = detector.rates.values().map(|r| r.rx_bps).sum();
        match sockets::established_rx_bps(Duration::from_secs(1)) {
            Some(bps) => {
                let share = if total_rx > 0.0 { bps / total_rx * 100.0 } else { 0.0 };
                println!(
                    "\nestablished TCP sockets receiving {} of {} inbound ({share:.0}% accounted)",
                    alert::fmt_bits(bps),
                    alert::fmt_bits(total_rx),
                );
            }
            None => println!("\nestablished TCP sockets: could not measure (ss unavailable)"),
        }
    }

    // Exact drop volume, which the ufw log cannot give: its LOG rule is rate
    // limited to 3/min, so the log counts its own limiter.
    match (snapshot_before, collector::read()) {
        (Some(before), Some(after)) => match after.drops_since(&before) {
            Some((packets, bytes)) if after.at > before.at => println!(
                "firewall dropped {packets} packets ({bytes} bytes) in {}s — exact",
                after.at - before.at
            ),
            _ => println!("firewall drops: collector has not refreshed yet"),
        },
        _ => println!(
            "firewall drops: unavailable — collector not installed \
             (crates/netwatch/collector/install-collector.sh)"
        ),
    }
}

fn selftest(cfg: Config) {
    let a = Alert {
        kind: "selftest",
        key: "selftest".to_string(),
        title: "netwatch selftest".to_string(),
        body: "If you can read this, notifications work.".to_string(),
        detail: "Emitted by --selftest, not by a detector.".to_string(),
        urgency: "normal",
    };
    alert::emit(&cfg, &a);
    println!("Emitted a test alert. See: journalctl --user -u netwatch");

    // The button's click handler runs in a thread this process owns. Exiting
    // now would leave a popup whose button does nothing — worse than offering
    // no button at all. The daemon has no such problem because it never exits,
    // so this wait exists purely to make --selftest exercise the real path.
    if cfg.notify {
        println!("Waiting 45s so the \"Open netwatch\" button works — Ctrl-C to skip.");
        thread::sleep(Duration::from_secs(45));
    }
}

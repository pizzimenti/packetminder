// =============================================================================
// collector — reads the snapshot the privileged half leaves in /run.
//
// Optional by construction. Everything here returns None when the collector is
// not installed, and every caller must carry on without it: the daemon shipped
// for months with no privileged component at all, and losing one must not turn
// into losing detection.
//
// What the snapshot buys, neither of which is reachable unprivileged:
//
//   conntrack_reply_bytes  covers UDP, which `ss` cannot -- it reports no byte
//                          counters for UDP sockets, so a QUIC transfer was
//                          uncorroborable and judged on ratio alone.
//   input_drop_*           exact firewall drop totals, where the ufw log is
//                          rate limited to 3/min and therefore counts its own
//                          limiter rather than the traffic.
//
// See collector/packetminder-collect for why the privileged side is a 60-line
// script rather than part of this binary.
// =============================================================================

use std::fs;

pub const SNAPSHOT_PATH: &str = "/run/packetminder/snapshot";

// -- Data Structures ----------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// Unix seconds the snapshot was written. Two samples with the same `at`
    /// are the same sample read twice, not a zero-length interval.
    pub at: i64,
    /// Whether net.netfilter.nf_conntrack_acct was on when the sample was
    /// taken. With it off the kernel emits no byte counters at all, so the
    /// totals below are not small -- they are absent.
    pub conntrack_acct: bool,
    pub conntrack_flows: u64,
    /// Monotonic. The collector accumulates per-flow increments precisely so
    /// this can be subtracted across expiries; see its comments for why summing
    /// the live table instead would go backwards.
    pub conntrack_reply_bytes: u64,
    pub input_drop_packets: u64,
    pub input_drop_bytes: u64,
}

impl Snapshot {
    /// Bits/sec of inbound that conntrack accounted for between two samples.
    ///
    /// None when the collector has not refreshed since `prev` — the timer runs
    /// every 5s and callers tick faster than that, so reading the same file
    /// twice is the common case, and inventing a zero rate from it would look
    /// exactly like "nothing is consuming this".
    /// Whether conntrack was in a position to measure anything at all.
    ///
    /// Blind, not quiet. Byte accounting off means every bytes= field is
    /// missing, and a zero built from missing fields would be reported as
    /// "conntrack watched and saw nothing consuming this" -- the exact sentence
    /// that turns a healthy UDP stream into a critical alert.
    ///
    /// Zero tracked flows says the same thing without needing the newer
    /// collector's acct field: conntrack contributed no information, so it
    /// cannot be cited as evidence of absence. A host receiving enough to reach
    /// the alert floor always has flows to show.
    pub fn measures_bytes(&self) -> bool {
        self.conntrack_acct && self.conntrack_flows > 0
    }

    pub fn reply_bps_since(&self, prev: &Snapshot) -> Option<f64> {
        // Both ends of the interval have to be measurable. A baseline taken
        // while conntrack was blind counted nothing, so a rate measured from it
        // spreads the measurable tail across the blind head and understates the
        // result -- which is the direction that invents false alerts.
        if !self.measures_bytes() || !prev.measures_bytes() {
            return None;
        }
        let elapsed = self.at.checked_sub(prev.at)?;
        if elapsed <= 0 {
            return None;
        }
        // A counter that went backwards means the collector restarted and lost
        // its accumulator. Treat that as unmeasured rather than as negative.
        let bytes = self
            .conntrack_reply_bytes
            .checked_sub(prev.conntrack_reply_bytes)?;
        Some(bytes as f64 * 8.0 / elapsed as f64)
    }

    /// Firewall drops between two samples, as (packets, bytes).
    pub fn drops_since(&self, prev: &Snapshot) -> Option<(u64, u64)> {
        Some((
            self.input_drop_packets
                .checked_sub(prev.input_drop_packets)?,
            self.input_drop_bytes.checked_sub(prev.input_drop_bytes)?,
        ))
    }
}

// -- Reading ------------------------------------------------------------------

/// The current snapshot, or None when the collector is not installed.
pub fn read() -> Option<Snapshot> {
    parse(&fs::read_to_string(SNAPSHOT_PATH).ok()?)
}

fn parse(text: &str) -> Option<Snapshot> {
    let mut at = None;
    // Absent means a collector older than the field. Assume accounting is on
    // and let the flows == 0 check carry the blind case, rather than silently
    // dropping corroboration on installs that were working fine.
    let mut acct = true;
    let mut flows = 0;
    let mut reply = 0;
    let mut drop_pkts = 0;
    let mut drop_bytes = 0;

    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let Ok(n) = value.trim().parse::<u64>() else {
            continue;
        };
        match key.trim() {
            "at" => at = Some(n as i64),
            "conntrack_acct" => acct = n != 0,
            "conntrack_flows" => flows = n,
            "conntrack_reply_bytes" => reply = n,
            "input_drop_packets" => drop_pkts = n,
            "input_drop_bytes" => drop_bytes = n,
            _ => {}
        }
    }

    // Without a timestamp nothing can be compared against anything, so a
    // snapshot missing it is not a partial snapshot -- it is unusable.
    Some(Snapshot {
        at: at?,
        conntrack_acct: acct,
        conntrack_flows: flows,
        conntrack_reply_bytes: reply,
        input_drop_packets: drop_pkts,
        input_drop_bytes: drop_bytes,
    })
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "at=1785890716\nconntrack_acct=1\nconntrack_flows=68\n\
                          conntrack_reply_bytes=6077902\n\
                          input_drop_packets=1884\ninput_drop_bytes=659578\n";

    #[test]
    fn parses_a_snapshot() {
        let s = parse(SAMPLE).expect("should parse");
        assert_eq!(s.at, 1785890716);
        assert_eq!(s.conntrack_reply_bytes, 6077902);
        assert_eq!(s.input_drop_packets, 1884);
    }

    /// The Moonlight false positive: a UDP stream that *was* being consumed,
    /// reported as unread because accounting was off and the resulting zero was
    /// mistaken for a measurement. Unmeasured must stay unmeasured.
    #[test]
    fn accounting_disabled_reads_as_unmeasured_not_as_zero() {
        let prev = parse("at=100\nconntrack_acct=0\nconntrack_flows=0\nconntrack_reply_bytes=0\n")
            .expect("should parse");
        let now = parse("at=110\nconntrack_acct=0\nconntrack_flows=0\nconntrack_reply_bytes=0\n")
            .expect("should parse");
        assert!(!now.conntrack_acct);
        assert_eq!(now.reply_bps_since(&prev), None);
    }

    /// An older collector predates the acct field, so zero flows has to carry
    /// the same meaning on its own.
    #[test]
    fn zero_flows_is_unmeasured_even_without_the_acct_field() {
        let prev = parse("at=100\nconntrack_flows=0\nconntrack_reply_bytes=0\n").expect("parses");
        let now = parse("at=110\nconntrack_flows=0\nconntrack_reply_bytes=0\n").expect("parses");
        assert!(now.conntrack_acct, "absent field assumes accounting is on");
        assert_eq!(now.reply_bps_since(&prev), None);
    }

    /// Turning accounting on mid-run must not produce a rate from an interval
    /// that began while nothing was being counted.
    #[test]
    fn the_first_measurable_sample_after_a_gap_yields_no_rate() {
        let blind = parse("at=100\nconntrack_acct=0\nconntrack_flows=0\nconntrack_reply_bytes=0\n")
            .expect("parses");
        let first =
            parse("at=110\nconntrack_acct=1\nconntrack_flows=9\nconntrack_reply_bytes=10000\n")
                .expect("parses");
        let second =
            parse("at=120\nconntrack_acct=1\nconntrack_flows=9\nconntrack_reply_bytes=20000\n")
                .expect("parses");

        // Measurable now, but the baseline was not: no rate.
        assert_eq!(first.reply_bps_since(&blind), None);
        // Both ends measurable: a rate, and one spanning only measured time.
        assert_eq!(second.reply_bps_since(&first), Some(8000.0));
    }

    /// A real measured zero -- flows tracked, accounting on, nothing consumed --
    /// must still be reported, or a genuine flood loses its corroboration.
    #[test]
    fn a_measured_zero_is_still_a_measurement() {
        let prev = parse("at=100\nconntrack_acct=1\nconntrack_flows=12\nconntrack_reply_bytes=500\n")
            .expect("parses");
        let now = parse("at=110\nconntrack_acct=1\nconntrack_flows=12\nconntrack_reply_bytes=500\n")
            .expect("parses");
        assert_eq!(now.reply_bps_since(&prev), Some(0.0));
    }

    #[test]
    fn survives_junk_and_new_keys() {
        // A future collector adding fields must not break an older daemon.
        let s = parse("at=100\nnonsense\nfuture_key=5\nconntrack_reply_bytes=abc\n")
            .expect("should parse");
        assert_eq!(s.at, 100);
        assert_eq!(s.conntrack_reply_bytes, 0);
        // No timestamp is the one unusable case.
        assert!(parse("conntrack_flows=3\n").is_none());
    }

    #[test]
    fn rates_need_two_distinct_samples() {
        let a = parse(SAMPLE).unwrap();
        let mut b = a;
        // Same file read twice: the collector has not refreshed.
        assert_eq!(a.reply_bps_since(&a), None);

        b.at += 10;
        b.conntrack_reply_bytes += 1_250_000;
        assert_eq!(b.reply_bps_since(&a), Some(1_000_000.0));

        // Collector restarted and lost its accumulator: unmeasured, not
        // negative.
        let mut c = b;
        c.at += 10;
        c.conntrack_reply_bytes = 5;
        assert_eq!(c.reply_bps_since(&b), None);
    }

    #[test]
    fn reads_the_real_snapshot_if_the_collector_is_installed() {
        // Absent collector is a supported configuration, so this asserts only
        // that reading never panics and that a present file parses.
        if std::path::Path::new(SNAPSHOT_PATH).exists() {
            assert!(read().is_some(), "installed collector wrote an unparseable snapshot");
        }
    }
}

// =============================================================================
// sockets — how much of the inbound traffic a socket can actually account for.
//
// The asymmetry detector asks "is anything here answering?" and answers it from
// interface counters alone. That cannot separate the two cases that matter:
//
//   a fast download   35 Mbps in, 600 Kbps out. Bulk TCP with delayed ACKs
//                     sends about one 66-byte ack per two 1514-byte frames, so
//                     ~2% outbound is exactly what health looks like.
//   a one-sided flood 35 Mbps in, 600 Kbps out, and nothing here asked for it.
//
// They are indistinguishable by ratio, because *they have the same ratio*. No
// threshold separates them; only a different question does. That question is:
// is there an established socket whose receive counter is climbing as fast as
// the interface's?
//
// If yes, the traffic is being consumed by something on this host, whatever the
// ratio says. If no, several megabits are arriving that no socket is reading,
// which is precisely the condition this daemon exists to report.
//
// Measured over a short window at alert time rather than sampled continuously,
// because it costs a process spawn and only matters when about to interrupt
// somebody.
//
// TCP only. `ss` reports no byte counters for UDP sockets, so a QUIC download
// cannot be corroborated this way and will still be judged on ratio alone.
// =============================================================================

use std::{collections::HashMap, process::Command, thread, time::Duration};

/// Bytes each established TCP socket has received, keyed by `local peer`.
type Received = HashMap<String, u64>;

/// Bits/sec that established TCP sockets received over `window`.
///
/// Returns None when `ss` cannot be run at all, which is different from zero —
/// the caller must not read "no sockets are reading" from "could not look".
pub fn established_rx_bps(window: Duration) -> Option<f64> {
    let first = read_received()?;
    thread::sleep(window);
    let second = read_received()?;

    let secs = window.as_secs_f64().max(0.001);
    let mut bytes = 0u64;
    for (key, later) in &second {
        // Only sockets present in *both* samples can contribute a delta. A
        // socket that opened or closed mid-window is skipped, which biases the
        // total low -- and low is the safe direction: undercounting what the
        // sockets explain means erring toward raising the alert, never toward
        // silently swallowing a real flood.
        if let Some(earlier) = first.get(key) {
            bytes += later.saturating_sub(*earlier);
        }
    }

    Some(bytes as f64 * 8.0 / secs)
}

/// Parse `ss -tin`, which prints a socket line then an indented info line:
///
///   ESTAB 0 0 10.3.252.119:35692 157.240.3.51:443
///        bbr wscale:8,10 rto:230 ... bytes_received:29619 segs_out:717 ...
fn read_received() -> Option<Received> {
    let out = Command::new("ss").args(["-tin"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);

    let mut received = Received::new();
    let mut key: Option<String> = None;

    for line in text.lines() {
        let indented = line.starts_with(char::is_whitespace);

        if !indented {
            // A socket line. Fields are State, Recv-Q, Send-Q, Local, Peer;
            // anything shorter is the header or a shape we do not understand.
            let fields: Vec<&str> = line.split_whitespace().collect();
            key = match (fields.first(), fields.get(3), fields.get(4)) {
                (Some(&"ESTAB"), Some(local), Some(peer)) => Some(format!("{local} {peer}")),
                _ => None,
            };
            continue;
        }

        // The info line belonging to the socket line above it.
        let Some(current) = key.take() else {
            continue;
        };
        if let Some(bytes) = field_value(line, "bytes_received:") {
            received.insert(current, bytes);
        }
    }

    Some(received)
}

/// Pull `name:<digits>` out of a whitespace-separated info line.
fn field_value(line: &str, name: &str) -> Option<u64> {
    line.split_whitespace()
        .find_map(|token| token.strip_prefix(name))
        .and_then(|v| v.parse().ok())
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pulls_named_fields_out_of_an_info_line() {
        let line = "\t bbr wscale:8,10 rto:230 bytes_sent:29955 bytes_received:29619 segs_out:717";
        assert_eq!(field_value(line, "bytes_received:"), Some(29619));
        assert_eq!(field_value(line, "bytes_sent:"), Some(29955));
        // A prefix that is not present, and one whose value is not a number.
        assert_eq!(field_value(line, "bytes_dreamed:"), None);
        assert_eq!(field_value(line, "wscale:"), None);
    }

    #[test]
    fn a_socket_with_no_info_line_contributes_nothing() {
        // Deltas need both samples; this is the property that keeps a socket
        // appearing or vanishing mid-window from inventing throughput.
        let mut first = Received::new();
        first.insert("a b".to_string(), 1000);
        let mut second = Received::new();
        second.insert("a b".to_string(), 3000);
        second.insert("c d".to_string(), 999_999); // opened mid-window

        let mut bytes = 0u64;
        for (key, later) in &second {
            if let Some(earlier) = first.get(key) {
                bytes += later.saturating_sub(*earlier);
            }
        }
        assert_eq!(bytes, 2000, "only the socket present in both samples counts");
    }

    #[test]
    fn reads_this_hosts_real_sockets() {
        // ss must be present and parseable; the count may legitimately be zero.
        assert!(read_received().is_some(), "ss -tin could not be parsed");
    }
}

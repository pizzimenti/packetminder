// =============================================================================
// discovery — answers to queries this host asked for, dropped on arrival.
//
// A default-deny INPUT chain drops a class of packet that is neither an
// intrusion nor a flood: the reply to a service-discovery query this host sent
// itself.
//
// Discovery protocols ask over multicast and are answered over unicast. The
// query leaves for 239.255.255.250:1900; the answer comes back from
// 10.3.193.195:1900. Conntrack tracked the first and cannot match the second —
// it is a different peer address entirely — so the reply arrives on the input
// path unsolicited and the firewall drops it.
//
// To the blocked-flow detector that looks exactly like what it exists to catch:
// repeated unicast UDP from one LAN host into a port with no conversation
// behind it. It is the opposite of that. Nobody is transmitting at this host;
// this host asked, and the answer is being thrown away on the doorstep.
//
// The tell is the *source* port. Each of these protocols answers from its own
// well-known port, and the answer lands on whatever ephemeral port the query
// went out from. A media device answering from udp/1900 to a high port is
// replying to an M-SEARCH; it is not probing.
//
// Naming the local program that asked is what makes the result actionable. The
// device in the title is the innocent party — it answered a question. The
// process holding the querying socket is the one whose discovery is quietly
// broken, and it is never the one the address points at.
// =============================================================================

use std::{collections::HashSet, fs, sync::OnceLock};

// -- The Port Table -----------------------------------------------------------

/// Ports that service-discovery protocols answer *from*.
///
/// Deliberately only protocols whose replies are unicast-to-ephemeral, because
/// that is the shape conntrack cannot match and therefore the only shape that
/// produces this false positive. A protocol answered on its own port round-trips
/// through conntrack correctly and never reaches here.
const DISCOVERY_PORTS: &[(u16, &str)] = &[
    (137, "NetBIOS name service"),
    (138, "NetBIOS datagram"),
    (1900, "SSDP"),
    (3702, "WS-Discovery"),
    (5353, "mDNS"),
    (5355, "LLMNR"),
    (6771, "BitTorrent local peer discovery"),
    (32412, "Plex GDM"),
    (32414, "Plex GDM"),
    (57621, "Spotify Connect discovery"),
];

/// Linux's usual ephemeral range floor, for when /proc cannot be read.
const DEFAULT_EPHEMERAL_FLOOR: u16 = 32768;

/// The lowest port the kernel actually allocates ephemeral source ports from.
///
/// A query this host sent went out from *this* range, so a reply arriving
/// anywhere else was not answering it. An earlier version accepted any
/// unprivileged port, which was far too generous: it treated every port above
/// 1024 as "somewhere a query might have come from", including the thousands of
/// ports that services listen on.
///
/// Read once. The range is a boot-time tunable in practice, and re-reading it
/// per packet would buy nothing.
fn ephemeral_floor() -> u16 {
    static FLOOR: OnceLock<u16> = OnceLock::new();
    *FLOOR.get_or_init(|| {
        fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
            .ok()
            .and_then(|text| text.split_whitespace().next()?.parse().ok())
            .unwrap_or(DEFAULT_EPHEMERAL_FLOOR)
    })
}

// -- Classification -----------------------------------------------------------

/// Name the discovery protocol a dropped packet is replying on, if it is one.
///
/// Every condition here is load-bearing:
///
/// - **UDP.** All of these are datagram protocols. A TCP drop with one of these
///   source ports is something else wearing the number.
/// - **On-link or private source.** Discovery does not cross a router. A reply
///   from the internet is not a reply to anything this host multicast.
/// - **Destination inside the kernel's ephemeral range.** The query's source
///   port is where the answer lands, and the kernel draws those from one
///   specific range. A flood *at* udp/1900 is a flood, and must stay visible.
/// - **Destination is not itself a discovery port.** Otherwise the announcement
///   traffic these protocols send between their own well-known ports would be
///   swallowed by the rule meant for their replies.
///
/// # What this cannot prove
///
/// A source port is chosen by the sender, so this is evidence, not proof. A
/// peer already on the LAN can send from udp/1900 into the ephemeral range
/// without this host ever having asked anything, and it will match here.
///
/// That is why matching alone does not silence anything: the caller pairs this
/// with whether a local socket is actually bound to the destination port, and
/// only that combination — a shape consistent with a reply *and* a socket that
/// would have received one — is quiet by default. See `compose_discovery_alert`.
/// The volume-sensitive detectors (`asymmetric-inbound`, `udp-no-listener`) read
/// interface and kernel counters rather than this log, and are unaffected by
/// anything decided here.
pub fn classify(proto: &str, sport: u16, dport: u16, nearby: bool) -> Option<&'static str> {
    if !proto.eq_ignore_ascii_case("UDP") || !nearby || dport < ephemeral_floor() {
        return None;
    }
    if named_port(dport).is_some() {
        return None;
    }
    named_port(sport)
}

fn named_port(port: u16) -> Option<&'static str> {
    DISCOVERY_PORTS
        .iter()
        .find(|(p, _)| *p == port)
        .map(|(_, name)| *name)
}

// -- Local Attribution --------------------------------------------------------

/// The command holding the socket a reply was addressed to, when one still is.
///
/// Two lookups: the port's socket inodes from /proc/net, then whichever process
/// has one of those inodes open. Unprivileged, and that is enough — the asking
/// program runs as the same user as this daemon in every case that matters,
/// since it is a desktop program doing desktop discovery. Other users' fd
/// directories deny us and are skipped rather than guessed at.
///
/// Returns None the moment no socket is bound, which is both correct and the
/// reason this is affordable: a reply that outlived its querying socket — the
/// common case for a discovery round that finished — costs two small reads and
/// never walks /proc at all.
///
/// Under `--replay` this reads *today's* socket table against historical
/// records, the same approximation `port_in_use` and the on-link test already
/// make. The journal does not record who held a port an hour ago.
pub fn asker(proto: &str, port: u16) -> Option<String> {
    let inodes = socket_inodes(proto, port);
    if inodes.is_empty() {
        return None;
    }
    process_holding(&inodes)
}

/// Socket inodes bound to `port`, formatted as the fd symlink target they will
/// appear as: `socket:[12345]`.
fn socket_inodes(proto: &str, port: u16) -> HashSet<String> {
    let files: &[&str] = match proto.to_ascii_uppercase().as_str() {
        "UDP" => &["udp", "udp6"],
        "TCP" => &["tcp", "tcp6"],
        _ => return HashSet::new(),
    };

    let mut inodes = HashSet::new();
    for name in files {
        let Ok(text) = fs::read_to_string(format!("/proc/net/{name}")) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // Column 1 is local_address as HEX_ADDR:HEX_PORT; column 9 is the
            // socket inode.
            let (Some(local), Some(inode)) = (fields.get(1), fields.get(9)) else {
                continue;
            };
            let Some((_, hex_port)) = local.rsplit_once(':') else {
                continue;
            };
            if u16::from_str_radix(hex_port, 16) == Ok(port) {
                inodes.insert(format!("socket:[{inode}]"));
            }
        }
    }
    inodes
}

/// Walk /proc for the first process with one of these sockets open.
///
/// First match wins. A socket shared across forked children resolves to
/// whichever is found first, which is fine: they share a command name, and the
/// command name is the whole answer.
fn process_holding(inodes: &HashSet<String>) -> Option<String> {
    for entry in fs::read_dir("/proc").ok()?.flatten() {
        let name = entry.file_name();
        let Some(pid) = name
            .to_str()
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        else {
            continue;
        };

        // Denied for other users' processes, and gone if the process exited
        // between the read_dir and here. Both are ordinary; skip and continue.
        let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            if inodes.contains(target.to_string_lossy().as_ref()) {
                return comm(pid);
            }
        }
    }
    None
}

fn comm(pid: &str) -> Option<String> {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_an_ssdp_reply_to_an_ephemeral_port() {
        // The real record: a Roku answering an M-SEARCH this host multicast.
        assert_eq!(classify("UDP", 1900, 43285, true), Some("SSDP"));
        assert_eq!(classify("UDP", 5353, 39325, true), Some("mDNS"));
    }

    #[test]
    fn a_reply_from_the_internet_is_not_a_reply_to_our_discovery() {
        // Discovery is link-local by construction, so an off-link source
        // claiming a discovery port is claiming something impossible.
        assert_eq!(classify("UDP", 1900, 43285, false), None);
    }

    #[test]
    fn traffic_aimed_at_a_service_port_stays_visible() {
        // A flood at udp/1900 itself, and the announcement traffic these
        // protocols send between their own well-known ports. Neither is a
        // unicast reply, and neither may be quietly reclassified.
        assert_eq!(classify("UDP", 1900, 1900, true), None);
        assert_eq!(classify("UDP", 5353, 5353, true), None);
        assert_eq!(classify("UDP", 1900, 500, true), None);
    }

    #[test]
    fn only_the_kernels_own_ephemeral_range_counts_as_a_query_source() {
        // Unprivileged but not ephemeral: no query this host sent could have
        // gone out from here, so a "reply" arriving here is answering nobody.
        // These are the ports an unlisted service is most likely to occupy.
        for dport in [1024, 3000, 8080, 8443, 25565] {
            assert_eq!(
                classify("UDP", 1900, dport, true),
                None,
                "udp/{dport} is below the ephemeral range and must stay visible"
            );
        }
        assert!(
            ephemeral_floor() >= DEFAULT_EPHEMERAL_FLOOR || ephemeral_floor() >= 1024,
            "a parsed range must still be a plausible ephemeral floor"
        );
        assert_eq!(classify("UDP", 1900, 43285, true), Some("SSDP"));
    }

    #[test]
    fn only_udp_and_only_listed_ports() {
        assert_eq!(classify("TCP", 1900, 43285, true), None);
        // The Sunshine flood this daemon was written for must never match.
        assert_eq!(classify("UDP", 47998, 37366, true), None);
    }

    #[test]
    fn attribution_is_free_when_no_socket_is_bound() {
        // Port 0 can never be bound, so this exercises the early return that
        // keeps the /proc walk off the common path.
        assert!(socket_inodes("UDP", 0).is_empty());
        assert_eq!(asker("UDP", 0), None);
        // A protocol with no /proc/net file cannot produce inodes either.
        assert!(socket_inodes("ICMP", 1900).is_empty());
    }

    #[test]
    fn finds_the_process_behind_a_socket_this_test_owns() {
        use std::net::UdpSocket;

        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind an ephemeral port");
        let port = socket.local_addr().expect("local addr").port();

        assert!(
            !socket_inodes("UDP", port).is_empty(),
            "a socket this process just bound must appear in /proc/net/udp"
        );
        // Whatever the harness calls the test binary, it is us, and the point
        // is that the inode resolved to a live process at all.
        assert!(asker("UDP", port).is_some(), "should name the holding process");
    }
}

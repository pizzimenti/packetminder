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

use std::{
    collections::HashSet,
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::OnceLock,
};

use crate::local::parse_ip;

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

/// Linux's usual ephemeral range, for when /proc cannot be read.
const DEFAULT_EPHEMERAL_RANGE: (u16, u16) = (32768, 60999);

/// The range the kernel actually allocates ephemeral source ports from.
///
/// A query this host sent went out from *inside* this range, so a reply
/// arriving anywhere else was not answering it. Both bounds matter. An earlier
/// version accepted any unprivileged port, which treated the thousands of
/// ports services listen on as places a query might have come from; the
/// version after that read only the floor, which left every port above the
/// kernel's ceiling — where services deliberately bind precisely because the
/// kernel will not hand them out — wearing the same disguise.
///
/// Read once. The range is a boot-time tunable in practice, and re-reading it
/// per packet would buy nothing.
fn ephemeral_range() -> (u16, u16) {
    static RANGE: OnceLock<(u16, u16)> = OnceLock::new();
    *RANGE.get_or_init(|| {
        fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
            .ok()
            .and_then(|text| {
                let mut fields = text.split_whitespace();
                let floor: u16 = fields.next()?.parse().ok()?;
                let ceiling: u16 = fields.next()?.parse().ok()?;
                // A backwards range is not a range; take the default over garbage.
                (floor <= ceiling).then_some((floor, ceiling))
            })
            .unwrap_or(DEFAULT_EPHEMERAL_RANGE)
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
/// - **Destination inside the kernel's ephemeral range — both ends of it.**
///   The query's source port is where the answer lands, and the kernel draws
///   those from one specific range. Below it live the ports services choose;
///   above its ceiling live the ports services choose *because* the kernel
///   will not hand them out. A flood at either is a flood, and must stay
///   visible.
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
    let (floor, ceiling) = ephemeral_range();
    if !proto.eq_ignore_ascii_case("UDP") || !nearby || dport < floor || dport > ceiling {
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

/// Whether a socket that could actually have received this packet is bound.
///
/// This is the corroboration the classifier cannot supply on its own. A source
/// port proves nothing — the sender picked it — but a local socket bound where
/// the packet was addressed is real evidence that something here asked.
///
/// The address half is load-bearing. Matching on the port alone counted a
/// socket bound to 127.0.0.1 as proof that a packet addressed to a LAN address
/// had been solicited, which it cannot be: a loopback socket never receives LAN
/// traffic. Only a wildcard binding, or one on the very address the packet was
/// sent to, can have been listening for it.
pub fn solicited_locally(proto: &str, dst: &str, port: u16) -> bool {
    !matching_inodes(proto, dst, port).is_empty()
}

/// The command holding the socket a reply was addressed to, when one still is.
///
/// Two lookups: the port's socket inodes from /proc/net, then whichever process
/// has one of those inodes open. Unprivileged, and that is enough — the asking
/// program runs as the same user as this daemon in every case that matters,
/// since it is a desktop program doing desktop discovery. Other users' fd
/// directories deny us and are skipped rather than guessed at.
///
/// Returns None the moment no socket matches, which is both correct and the
/// reason this is affordable: a reply that outlived its querying socket — the
/// common case for a discovery round that finished — costs two small reads and
/// never walks /proc at all.
///
/// Under `--replay` this reads *today's* socket table against historical
/// records, the same approximation the on-link test already makes. The journal
/// does not record who held a port an hour ago, and `--replay` says so.
pub fn asker(proto: &str, dst: &str, port: u16) -> Option<String> {
    let inodes = matching_inodes(proto, dst, port);
    if inodes.is_empty() {
        return None;
    }
    process_holding(&inodes)
}

/// Socket inodes bound to `port` on an address that could have received a
/// packet sent to `dst`, formatted as the fd symlink target they will appear
/// as: `socket:[12345]`.
fn matching_inodes(proto: &str, dst: &str, port: u16) -> HashSet<String> {
    let files: &[&str] = match proto.to_ascii_uppercase().as_str() {
        "UDP" => &["udp", "udp6"],
        "TCP" => &["tcp", "tcp6"],
        _ => return HashSet::new(),
    };
    let destination = parse_ip(dst);

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
            let Some((hex_addr, hex_port)) = local.rsplit_once(':') else {
                continue;
            };
            if u16::from_str_radix(hex_port, 16) != Ok(port) {
                continue;
            }
            let Some(bound) = parse_proc_addr(hex_addr) else {
                continue;
            };
            if could_receive(&bound, destination) {
                inodes.insert(format!("socket:[{inode}]"));
            }
        }
    }
    inodes
}

/// Whether a socket bound to `local` could have received a packet sent to
/// `destination`.
///
/// A wildcard is a wildcard only within its own family. `0.0.0.0` and `[::]`
/// both answer `is_unspecified()`, but an IPv4 wildcard never sees a single
/// IPv6 packet — and the reverse, an IPv6 wildcard taking v4-mapped traffic,
/// is true only when the socket is dual-stack, which `IPV6_V6ONLY` turns off
/// per socket and `net.ipv6.bindv6only` per host, neither visibly in
/// /proc/net. A claim that cannot be checked is not corroboration, so the
/// cross-family match is refused outright: the rare dual-stack-only program
/// costs a popup where quiet was deserved, which is the direction this
/// detector is allowed to be wrong in. Otherwise the addresses have to be the
/// same one, and an unparseable destination corroborates nothing.
fn could_receive(local: &IpAddr, destination: Option<IpAddr>) -> bool {
    match (local, destination) {
        (_, None) => false,
        (IpAddr::V4(bound), Some(IpAddr::V4(_))) if bound.is_unspecified() => true,
        (IpAddr::V6(bound), Some(IpAddr::V6(_))) if bound.is_unspecified() => true,
        (bound, Some(dst)) => *bound == dst,
    }
}

/// Parse the hex local address /proc/net writes: a little-endian u32 per word,
/// 8 hex characters for IPv4 and 32 for IPv6.
fn parse_proc_addr(hex: &str) -> Option<IpAddr> {
    match hex.len() {
        8 => {
            let raw = u32::from_str_radix(hex, 16).ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(raw.swap_bytes())))
        }
        32 => {
            let mut octets = [0u8; 16];
            for (word, chunk) in hex.as_bytes().chunks(8).enumerate() {
                let text = std::str::from_utf8(chunk).ok()?;
                let raw = u32::from_str_radix(text, 16).ok()?;
                octets[word * 4..word * 4 + 4].copy_from_slice(&raw.swap_bytes().to_be_bytes());
            }
            let addr = Ipv6Addr::from(octets);
            // A dual-stack socket bound to a v4 address shows up here as
            // v4-mapped. Unlike a bare [::], that binding is *provably*
            // v4-capable — IPV6_V6ONLY refuses mapped bindings outright — so
            // canonicalising it is a checkable claim, and leaving it V6 would
            // fail the family comparison against the v4 packet it is
            // legitimately waiting for.
            Some(match addr.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(addr),
            })
        }
        _ => None,
    }
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
        let (floor, ceiling) = ephemeral_range();

        // Unprivileged but not ephemeral: no query this host sent could have
        // gone out from here, so a "reply" arriving here is answering nobody.
        // These are the ports an unlisted service is most likely to occupy.
        for dport in [1024, 3000, 8080, 8443, 25565] {
            assert!(
                dport < floor,
                "test premise: udp/{dport} sits below the ephemeral range"
            );
            assert_eq!(
                classify("UDP", 1900, dport, true),
                None,
                "udp/{dport} is below the ephemeral range and must stay visible"
            );
        }

        // The ceiling binds too. Services bind above it precisely because the
        // kernel will not hand those ports out, so a "reply" landing there is
        // aimed at a service, not at a query's return address.
        if ceiling < u16::MAX {
            assert_eq!(
                classify("UDP", 1900, ceiling + 1, true),
                None,
                "udp/{} is above the ephemeral range and must stay visible",
                ceiling + 1
            );
        }
        // The interior of the real range classifies — stepping off any port
        // that happens to be in the discovery table itself.
        let mut inside = floor.midpoint(ceiling);
        while named_port(inside).is_some() {
            inside += 1;
        }
        assert_eq!(classify("UDP", 1900, inside, true), Some("SSDP"));
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
        assert!(matching_inodes("UDP", "10.3.153.246", 0).is_empty());
        assert_eq!(asker("UDP", "10.3.153.246", 0), None);
        // A protocol with no /proc/net file cannot produce inodes either.
        assert!(matching_inodes("ICMP", "10.3.153.246", 1900).is_empty());
    }

    #[test]
    fn finds_the_process_behind_a_socket_this_test_owns() {
        use std::net::UdpSocket;

        // Wildcard, which is what a real discovery client binds — and what can
        // legitimately corroborate a packet sent to any local address.
        let socket = UdpSocket::bind("0.0.0.0:0").expect("bind an ephemeral port");
        let port = socket.local_addr().expect("local addr").port();

        assert!(
            solicited_locally("UDP", "10.3.153.246", port),
            "a wildcard socket this process just bound must corroborate"
        );
        // Whatever the harness calls the test binary, it is us, and the point
        // is that the inode resolved to a live process at all.
        assert!(
            asker("UDP", "10.3.153.246", port).is_some(),
            "should name the holding process"
        );
    }

    #[test]
    fn a_loopback_socket_cannot_corroborate_a_packet_from_the_lan() {
        use std::net::UdpSocket;

        // The hole an earlier version had: matching on the port alone counted
        // this socket as proof that a packet addressed to a LAN address had
        // been asked for. It cannot be — a loopback socket never receives LAN
        // traffic — so a peer picking a coincidentally-occupied port would have
        // been silenced.
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind loopback");
        let port = socket.local_addr().expect("local addr").port();

        assert!(
            !solicited_locally("UDP", "10.3.153.246", port),
            "a loopback binding must not corroborate LAN-addressed traffic"
        );
        // It does corroborate traffic actually addressed to loopback.
        assert!(
            solicited_locally("UDP", "127.0.0.1", port),
            "the same socket does account for loopback-addressed traffic"
        );
    }

    #[test]
    fn a_wildcard_is_only_a_wildcard_within_its_own_family() {
        use std::net::{Ipv4Addr, Ipv6Addr};

        let v4_any = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let v6_any = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        let v4_dst = parse_ip("10.3.153.246");
        let v6_dst = parse_ip("fe80:0000:0000:0000:b787:4f5d:1cbb:eb39");

        // 0.0.0.0 and [::] both answer is_unspecified(), but neither reaches
        // across families as far as anything in /proc/net can prove.
        assert!(could_receive(&v4_any, v4_dst));
        assert!(
            !could_receive(&v4_any, v6_dst),
            "a v4-only wildcard never sees an IPv6 packet and must not corroborate one"
        );
        assert!(could_receive(&v6_any, v6_dst));
        assert!(
            !could_receive(&v6_any, v4_dst),
            "whether a [::] socket takes v4-mapped traffic depends on IPV6_V6ONLY, \
             which /proc/net does not show — an uncheckable claim corroborates nothing"
        );

        // No wildcard corroborates a destination that did not parse.
        assert!(!could_receive(&v6_any, None));
        assert!(!could_receive(&v4_any, None));
    }

    #[test]
    fn reads_the_byte_order_proc_writes_addresses_in() {
        assert_eq!(
            parse_proc_addr("0100007F"),
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        );
        assert_eq!(
            parse_proc_addr("00000000"),
            Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        );
        // 10.3.153.246, as the kernel writes it.
        assert_eq!(
            parse_proc_addr("F699030A"),
            Some(IpAddr::V4(Ipv4Addr::new(10, 3, 153, 246)))
        );
        assert_eq!(
            parse_proc_addr("00000000000000000000000001000000"),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        // A dual-stack socket bound to a v4 address appears v4-mapped, and is
        // canonicalised to the v4 address it is provably able to receive on.
        assert_eq!(
            parse_proc_addr("0000000000000000FFFF0000F699030A"),
            Some(IpAddr::V4(Ipv4Addr::new(10, 3, 153, 246)))
        );
        assert_eq!(parse_proc_addr("nonsense"), None);
    }
}

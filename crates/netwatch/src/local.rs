// =============================================================================
// local — which addresses belong to this host, and which are group addresses.
//
// The blocked-flow detector answers one question: who is transmitting into a
// port nothing is listening on? Two whole classes of drop record cannot answer
// it, and both look identical to a real flood once DST has been discarded:
//
//   self-sourced     The kernel loops a locally-generated multicast packet back
//                    into INPUT, where a default-deny firewall drops and logs
//                    it. SRC is one of our own addresses and the record has no
//                    MAC= field, because the packet never reached the wire.
//                    Nobody is transmitting at us; we are talking to ourselves.
//
//   group-addressed  224.0.0.0/4, ff00::/8, 255.255.255.255 and the subnet
//                    broadcast are shouted at the entire segment. LLMNR, mDNS,
//                    SSDP and NetBIOS do this continuously by design. A drop
//                    means "this host did not subscribe", not "this traffic was
//                    misdirected at this host".
//
// Filtering these is not a heuristic — it is the detector's premise. An alert
// about either is false by construction, and a detector that cries wolf about
// its own LLMNR queries is one that gets muted.
//
// Knowing our own addresses answers a third question the alert text depends on:
// is a source a neighbour or a stranger? Under IPv4 an address class settles it,
// because RFC1918 space is not routable. Under IPv6 it does not settle anything
// — there is no NAT, so the machine on the next desk holds a globally-routable
// address that whois will attribute to an ISP. Only a shared prefix separates
// them, which is why assigned prefix lengths are kept and not just addresses.
// =============================================================================

use std::{collections::HashSet, net::IpAddr, process::Command};

/// How long a detected address set is trusted before being re-read. A DHCP
/// lease change or a VPN interface coming up both move it mid-run.
const REFRESH_SECS: i64 = 60;

// -- Data Structures ----------------------------------------------------------

#[derive(Default)]
struct Addrs {
    /// Every address currently assigned to any interface on this host.
    addrs: HashSet<IpAddr>,
    /// Per-interface IPv4 broadcast addresses, e.g. 10.3.255.255 for a /16.
    broadcasts: HashSet<IpAddr>,
    /// Each assigned address with its prefix length, i.e. the subnets this
    /// host is directly attached to.
    networks: Vec<(IpAddr, u8)>,
}

pub struct LocalNet {
    have: Addrs,
    refreshed: i64,
}

impl LocalNet {
    pub fn detect(now: i64) -> Self {
        Self {
            have: read_addrs(),
            refreshed: now,
        }
    }

    /// Build a fixed set directly, bypassing `ip`. Used by tests.
    ///
    /// Addresses are written in CIDR form so a test can express which subnet
    /// this host is attached to, which is what `is_on_link` turns on.
    #[cfg(test)]
    pub fn from_parts(networks: &[&str], broadcasts: &[&str]) -> Self {
        let networks: Vec<(IpAddr, u8)> = networks.iter().filter_map(|s| parse_cidr(s)).collect();
        Self {
            have: Addrs {
                addrs: networks.iter().map(|(ip, _)| *ip).collect(),
                broadcasts: broadcasts.iter().filter_map(|s| parse_ip(s)).collect(),
                networks,
            },
            refreshed: i64::MAX, // never stale: tests must not shell out
        }
    }

    pub fn refresh_if_stale(&mut self, now: i64) {
        if now.saturating_sub(self.refreshed) < REFRESH_SECS {
            return;
        }
        let fresh = read_addrs();
        // An empty read means `ip` is missing or failed. Keeping the previous
        // set is strictly better than filtering nothing at all.
        if !fresh.addrs.is_empty() {
            self.have = fresh;
        }
        self.refreshed = now;
    }

    /// Is this address assigned to this host?
    pub fn is_local(&self, ip: &IpAddr) -> bool {
        self.have.addrs.contains(ip) || ip.is_loopback()
    }

    /// Is this address aimed at a group rather than at one host?
    pub fn is_group(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                v4.is_multicast() || v4.is_broadcast() || self.have.broadcasts.contains(ip)
            }
            IpAddr::V6(v6) => v6.is_multicast(),
        }
    }

    /// Does this address sit on a subnet this host is directly attached to?
    ///
    /// This is the only test that identifies a neighbour under IPv6. There is
    /// no NAT there, so a machine one hop away holds a globally-routable
    /// address indistinguishable from a server on another continent — by
    /// address class alone. Sharing a prefix with one of our own addresses is
    /// what actually distinguishes them.
    ///
    /// Concretely: `2605:59ca:3307:0c08:8255:…` looks like the public internet
    /// and whois will happily name the ISP that owns the allocation, but this
    /// host held `2605:59ca:3307:0c08:0db3:…` on the same /64, so it was a
    /// machine on the same switch.
    pub fn is_on_link(&self, ip: &IpAddr) -> bool {
        self.have
            .networks
            .iter()
            .any(|(local, prefix_len)| shares_prefix(ip, local, *prefix_len))
    }
}

/// Do two addresses agree on their first `prefix_len` bits?
fn shares_prefix(a: &IpAddr, b: &IpAddr, prefix_len: u8) -> bool {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => bits_match(&a.octets(), &b.octets(), prefix_len),
        (IpAddr::V6(a), IpAddr::V6(b)) => bits_match(&a.octets(), &b.octets(), prefix_len),
        // Different families never share a prefix, whatever the bits say.
        _ => false,
    }
}

fn bits_match(a: &[u8], b: &[u8], prefix_len: u8) -> bool {
    let whole = (prefix_len / 8) as usize;
    let leftover = prefix_len % 8;
    if whole > a.len() {
        return false; // nonsense prefix length; refuse rather than guess
    }
    if a[..whole] != b[..whole] {
        return false;
    }
    if leftover == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - leftover);
    (a[whole] ^ b[whole]) & mask == 0
}

// -- Address Discovery --------------------------------------------------------

/// Read assigned addresses and broadcast addresses from `ip -o addr show`.
///
/// One line per address, e.g.
///   2: wlp1s0    inet 10.3.153.246/16 brd 10.3.255.255 scope global dynamic …
fn read_addrs() -> Addrs {
    let mut have = Addrs::default();

    let Ok(out) = Command::new("ip").args(["-o", "addr", "show"]).output() else {
        eprintln!("netwatch: cannot run `ip addr`; self-sourced drops will not be filtered");
        return have;
    };

    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let mut tokens = line.split_whitespace();
        while let Some(token) = tokens.next() {
            match token {
                "inet" | "inet6" => {
                    // Value is addr/prefixlen. Both halves matter: the address
                    // identifies us, the prefix identifies our segment.
                    if let Some((ip, prefix_len)) = tokens.next().and_then(parse_cidr) {
                        have.addrs.insert(ip);
                        have.networks.push((ip, prefix_len));
                    }
                }
                "brd" => {
                    if let Some(ip) = tokens.next().and_then(parse_ip) {
                        have.broadcasts.insert(ip);
                    }
                }
                _ => {}
            }
        }
    }

    have
}

/// Every IPv6 address currently assigned, loopback excluded.
///
/// Link-local counts rather than being filtered as a detail: `fe80::…`
/// appearing on an interface means the IPv6 stack came up there, which is
/// precisely the event worth noticing on a host that is trying to keep IPv6
/// off. Something re-enabling it is not hypothetical here — 66 of this
/// machine's 82 saved connection profiles carry `ipv6.method=auto`, and
/// NetworkManager clears `disable_ipv6` per interface for every one of them.
pub fn ipv6_addrs() -> HashSet<IpAddr> {
    read_addrs()
        .addrs
        .into_iter()
        .filter(|ip| ip.is_ipv6() && !ip.is_loopback())
        .collect()
}

/// Parse `addr/prefixlen`. A bare address is treated as a host route, which is
/// what `ip` means when it omits the prefix.
fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let (addr, prefix) = match s.split_once('/') {
        Some((addr, prefix)) => (addr, Some(prefix)),
        None => (s, None),
    };
    let ip = parse_ip(addr)?;

    let full_width = if ip.is_ipv4() { 32 } else { 128 };
    let prefix_len = match prefix {
        Some(p) => p.parse().ok()?,
        None => full_width,
    };
    if prefix_len > full_width {
        return None;
    }
    Some((ip, prefix_len))
}

/// Parse an address as written by either `ip` or the kernel log.
///
/// These disagree on IPv6 formatting: `ip` prints `fe80::b787:4f5d:1cbb:eb39`
/// while netfilter prints it fully expanded as
/// `fe80:0000:0000:0000:b787:4f5d:1cbb:eb39`. Comparing the strings would never
/// match; comparing parsed addresses always does.
pub fn parse_ip(s: &str) -> Option<IpAddr> {
    s.parse().ok()
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// This host as it was configured on 2026-08-03: wifi and wired on the same
    /// /16, a Tailscale host route, and a globally-routable Starlink /64.
    fn net() -> LocalNet {
        LocalNet::from_parts(
            &[
                "10.3.153.246/16",
                "10.3.252.119/16",
                "100.99.85.125/32",
                "fe80::b787:4f5d:1cbb:eb39/64",
                "2605:59ca:3307:0c08:0db3:51a1:2ab9:acd1/64",
            ],
            &["10.3.255.255"],
        )
    }

    #[test]
    fn recognises_its_own_addresses() {
        let n = net();
        assert!(n.is_local(&parse_ip("10.3.153.246").unwrap()));
        assert!(n.is_local(&parse_ip("100.99.85.125").unwrap()));
        assert!(n.is_local(&parse_ip("127.0.0.1").unwrap()));
        assert!(!n.is_local(&parse_ip("10.3.59.7").unwrap()));
    }

    #[test]
    fn matches_expanded_ipv6_from_the_kernel_log() {
        // `ip` prints the compressed form, netfilter the expanded one.
        let n = net();
        let expanded = parse_ip("fe80:0000:0000:0000:b787:4f5d:1cbb:eb39").unwrap();
        assert!(n.is_local(&expanded));
    }

    #[test]
    fn a_global_ipv6_neighbour_is_on_link() {
        // The real case: a Tailscale peer one hop away, holding a routable
        // Starlink address on the same /64 this host was assigned. whois names
        // SpaceX and no address-class test can tell it from a remote server —
        // only the shared prefix can.
        let n = net();
        let peer = parse_ip("2605:59ca:3307:0c08:8255:9b0a:8843:f2b1").unwrap();
        assert!(n.is_on_link(&peer));

        // Same allocation, different /64: routed, not on our segment.
        let elsewhere = parse_ip("2605:59ca:3307:0c09:8255:9b0a:8843:f2b1").unwrap();
        assert!(!n.is_on_link(&elsewhere));
    }

    #[test]
    fn ipv4_neighbours_and_strangers_are_told_apart() {
        let n = net();
        // Same /16 as both wifi and wired.
        assert!(n.is_on_link(&parse_ip("10.3.59.7").unwrap()));
        // Private, but not a subnet this host is attached to.
        assert!(!n.is_on_link(&parse_ip("192.168.1.5").unwrap()));
        assert!(!n.is_on_link(&parse_ip("8.8.8.8").unwrap()));
        // The Tailscale address is a /32, so it brings no neighbours with it.
        assert!(!n.is_on_link(&parse_ip("100.99.85.126").unwrap()));
    }

    #[test]
    fn families_never_share_a_prefix() {
        // 10.3.x as v4 bytes must not match anything in a v6 comparison.
        let n = net();
        assert!(!n.is_on_link(&parse_ip("::ffff:10.3.59.7").unwrap()));
    }

    #[test]
    fn recognises_group_addresses() {
        let n = net();
        // LLMNR over IPv4, LLMNR over IPv6, limited broadcast, subnet broadcast.
        assert!(n.is_group(&parse_ip("224.0.0.252").unwrap()));
        assert!(n.is_group(&parse_ip("ff02:0000:0000:0000:0000:0000:0001:0003").unwrap()));
        assert!(n.is_group(&parse_ip("255.255.255.255").unwrap()));
        assert!(n.is_group(&parse_ip("10.3.255.255").unwrap()));
        // A plain unicast neighbour is not a group.
        assert!(!n.is_group(&parse_ip("10.3.59.7").unwrap()));
    }
}

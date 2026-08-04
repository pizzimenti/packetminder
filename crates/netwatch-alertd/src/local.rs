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
// =============================================================================

use std::{collections::HashSet, net::IpAddr, process::Command};

/// How long a detected address set is trusted before being re-read. A DHCP
/// lease change or a VPN interface coming up both move it mid-run.
const REFRESH_SECS: i64 = 60;

// -- Data Structures ----------------------------------------------------------

pub struct LocalNet {
    /// Every address currently assigned to any interface on this host.
    addrs: HashSet<IpAddr>,
    /// Per-interface IPv4 broadcast addresses, e.g. 10.3.255.255 for a /16.
    broadcasts: HashSet<IpAddr>,
    refreshed: i64,
}

impl LocalNet {
    pub fn detect(now: i64) -> Self {
        let (addrs, broadcasts) = read_addrs();
        Self {
            addrs,
            broadcasts,
            refreshed: now,
        }
    }

    /// Build a fixed set directly, bypassing `ip`. Used by tests.
    #[cfg(test)]
    pub fn from_parts(addrs: &[&str], broadcasts: &[&str]) -> Self {
        Self {
            addrs: addrs.iter().filter_map(|s| parse_ip(s)).collect(),
            broadcasts: broadcasts.iter().filter_map(|s| parse_ip(s)).collect(),
            refreshed: i64::MAX, // never stale: tests must not shell out
        }
    }

    pub fn refresh_if_stale(&mut self, now: i64) {
        if now.saturating_sub(self.refreshed) < REFRESH_SECS {
            return;
        }
        let (addrs, broadcasts) = read_addrs();
        // An empty read means `ip` is missing or failed. Keeping the previous
        // set is strictly better than filtering nothing at all.
        if !addrs.is_empty() {
            self.addrs = addrs;
            self.broadcasts = broadcasts;
        }
        self.refreshed = now;
    }

    /// Is this address assigned to this host?
    pub fn is_local(&self, ip: &IpAddr) -> bool {
        self.addrs.contains(ip) || ip.is_loopback()
    }

    /// Is this address aimed at a group rather than at one host?
    pub fn is_group(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => v4.is_multicast() || v4.is_broadcast() || self.broadcasts.contains(ip),
            IpAddr::V6(v6) => v6.is_multicast(),
        }
    }
}

// -- Address Discovery --------------------------------------------------------

/// Read assigned addresses and broadcast addresses from `ip -o addr show`.
///
/// One line per address, e.g.
///   2: wlp1s0    inet 10.3.153.246/16 brd 10.3.255.255 scope global dynamic …
fn read_addrs() -> (HashSet<IpAddr>, HashSet<IpAddr>) {
    let mut addrs = HashSet::new();
    let mut broadcasts = HashSet::new();

    let Ok(out) = Command::new("ip").args(["-o", "addr", "show"]).output() else {
        eprintln!("netwatch-alertd: cannot run `ip addr`; self-sourced drops will not be filtered");
        return (addrs, broadcasts);
    };

    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let mut tokens = line.split_whitespace();
        while let Some(token) = tokens.next() {
            match token {
                "inet" | "inet6" => {
                    // Value is addr/prefixlen; the prefix is not needed because
                    // `brd` gives us the broadcast address directly.
                    if let Some(value) = tokens.next()
                        && let Some(ip) = parse_ip(value.split('/').next().unwrap_or(value))
                    {
                        addrs.insert(ip);
                    }
                }
                "brd" => {
                    if let Some(ip) = tokens.next().and_then(parse_ip) {
                        broadcasts.insert(ip);
                    }
                }
                _ => {}
            }
        }
    }

    (addrs, broadcasts)
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

    fn net() -> LocalNet {
        LocalNet::from_parts(
            &["10.3.153.246", "100.99.85.125", "fe80::b787:4f5d:1cbb:eb39"],
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

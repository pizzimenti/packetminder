// =============================================================================
// role — is this host an endpoint, or is it passing traffic through?
//
// Every detector here assumes traffic arriving is traffic *for this host*. That
// assumption breaks the moment the kernel starts forwarding:
//
//   endpoint   inbound on an interface should be answered on the same
//              interface, so rx without tx means nobody here is participating.
//   routing    inbound on the uplink leaves via the LAN side and vice versa, so
//              per-interface rx-without-tx is the normal, correct shape of a
//              router. Judging each interface alone would report a working
//              hotspot as a flood on both of its interfaces at once.
//
// This matters even on a laptop that is usually an endpoint, because the role
// changes underneath you: enabling connection sharing or a hotspot flips
// ip_forward, and nothing tells the daemon. So the role is re-read on every
// tick rather than sampled once at startup.
//
// Dual-homing is the milder cousin. Two interfaces on one subnet do not break
// the asymmetry maths -- each still measures its own traffic -- but they do
// mean "which interface" stops being a reliable way to tell two devices apart,
// and they produce ARP flux. Worth reporting, not worth compensating for.
// =============================================================================

use std::{fs, process::Command};

// -- Forwarding ---------------------------------------------------------------

/// True when the kernel forwards for any interface, v4 or v6.
///
/// Checks `all` as well as the per-interface knobs: enabling a hotspot commonly
/// sets forwarding on just the two interfaces involved, leaving the global flag
/// at zero, so reading only `net.ipv4.ip_forward` would miss it.
pub fn is_forwarding() -> bool {
    !forwarding_ifaces().is_empty()
}

/// Interfaces with forwarding enabled, `all` included when it is set.
pub fn forwarding_ifaces() -> Vec<String> {
    let mut out = Vec::new();
    for family in ["ipv4", "ipv6"] {
        let base = format!("/proc/sys/net/{family}/conf");
        let Ok(entries) = fs::read_dir(&base) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            // `default` is a template for future interfaces, not a live one.
            if name == "default" {
                continue;
            }
            if flag_set(&format!("{base}/{name}/forwarding")) && !out.contains(&name) {
                out.push(name);
            }
        }
    }
    out.sort();
    out
}

fn flag_set(path: &str) -> bool {
    fs::read_to_string(path)
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

// -- Dual homing --------------------------------------------------------------

/// Interfaces that share a subnet, as `"10.3.0.0/16: enp3s0f3u2, wlp1s0"`.
///
/// Two interfaces on one layer-2 network answer ARP for each other's addresses
/// by default, so replies can leave the interface a request did not arrive on.
pub fn shared_subnets() -> Vec<String> {
    let Ok(out) = Command::new("ip").args(["-o", "addr", "show"]).output() else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&out.stdout);

    // subnet → interfaces on it
    let mut by_subnet: Vec<(String, Vec<String>)> = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // "1: lo    inet 127.0.0.1/8 scope host lo"
        let (Some(iface), Some(family), Some(cidr)) =
            (fields.get(1), fields.get(2), fields.get(3))
        else {
            continue;
        };
        if *family != "inet" && *family != "inet6" {
            continue;
        }
        let Some(subnet) = network_of(cidr) else {
            continue;
        };
        // Loopback and link-local share prefixes by definition, and say nothing.
        if subnet.starts_with("127.") || subnet.starts_with("fe80:") || subnet == "::1/128" {
            continue;
        }

        match by_subnet.iter_mut().find(|(s, _)| *s == subnet) {
            Some((_, ifaces)) => {
                if !ifaces.iter().any(|i| i == iface) {
                    ifaces.push((*iface).to_string());
                }
            }
            None => by_subnet.push((subnet, vec![(*iface).to_string()])),
        }
    }

    by_subnet
        .into_iter()
        .filter(|(_, ifaces)| ifaces.len() > 1)
        .map(|(subnet, ifaces)| format!("{subnet}: {}", ifaces.join(", ")))
        .collect()
}

/// `10.3.252.119/16` → `10.3.0.0/16`. Returns None for anything unparseable,
/// which is the right answer for a line this does not understand.
fn network_of(cidr: &str) -> Option<String> {
    let (addr, prefix) = cidr.split_once('/')?;
    let bits: u32 = prefix.parse().ok()?;

    if let Ok(v4) = addr.parse::<std::net::Ipv4Addr>() {
        if bits > 32 {
            return None;
        }
        // Shifting by 32 is undefined, so a /0 masks to nothing explicitly.
        let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
        let net = u32::from(v4) & mask;
        return Some(format!("{}/{bits}", std::net::Ipv4Addr::from(net)));
    }

    if let Ok(v6) = addr.parse::<std::net::Ipv6Addr>() {
        if bits > 128 {
            return None;
        }
        let mask = if bits == 0 {
            0u128
        } else {
            u128::MAX << (128 - bits)
        };
        let net = u128::from(v6) & mask;
        return Some(format!("{}/{bits}", std::net::Ipv6Addr::from(net)));
    }

    None
}

// -- Reporting ----------------------------------------------------------------

/// One line for the startup log and `--status`.
pub fn describe() -> String {
    let mut parts = Vec::new();

    let fwd = forwarding_ifaces();
    if fwd.is_empty() {
        parts.push("endpoint (not forwarding)".to_string());
    } else {
        parts.push(format!("ROUTING via {}", fwd.join(", ")));
    }

    let shared = shared_subnets();
    if !shared.is_empty() {
        parts.push(format!("dual-homed [{}]", shared.join("; ")));
    }

    parts.join(" — ")
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_addresses_down_to_their_network() {
        assert_eq!(network_of("10.3.252.119/16").as_deref(), Some("10.3.0.0/16"));
        assert_eq!(network_of("10.3.153.246/16").as_deref(), Some("10.3.0.0/16"));
        // The two interfaces on this host land on the same network, which is
        // exactly the condition shared_subnets() reports.
        assert_eq!(network_of("192.168.1.7/24").as_deref(), Some("192.168.1.0/24"));
        assert_eq!(network_of("2605:59ca:3307:c08::1/64").as_deref(), Some("2605:59ca:3307:c08::/64"));
    }

    #[test]
    fn edge_prefixes_do_not_panic() {
        // Shifting a u32 by 32 is undefined behaviour in the naive version.
        assert_eq!(network_of("10.0.0.1/0").as_deref(), Some("0.0.0.0/0"));
        assert_eq!(network_of("10.0.0.1/32").as_deref(), Some("10.0.0.1/32"));
        assert_eq!(network_of("garbage").is_none(), true);
        assert_eq!(network_of("10.0.0.1/33").is_none(), true);
    }

    #[test]
    fn forwarding_reads_the_real_kernel_state() {
        // Whatever this host is doing, the call must not panic and must agree
        // with itself.
        let ifaces = forwarding_ifaces();
        assert_eq!(is_forwarding(), !ifaces.is_empty());
    }
}

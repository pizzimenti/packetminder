# Changelog

All notable changes to packetminder are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **`discovery-reply`: a LAN device answering a query this host asked is no
  longer reported as a device flooding it.** Discovery protocols ask over
  multicast and are answered over unicast, so conntrack cannot match the reply
  and a default-deny firewall drops it. The record that reaches the log is
  unicast, from a neighbour, addressed to this host and sustained — the exact
  signature `blocked-flow` exists to catch, meaning the opposite. Recognised
  from the source port (SSDP, mDNS, WS-Discovery, LLMNR, NetBIOS, BitTorrent
  LSD, Plex GDM, Spotify Connect) together with an on-link source and an
  ephemeral destination; a flood *at* one of those ports still alerts normally.
- **The alert names the local process that asked**, resolved through
  `/proc/net/udp` to `/proc/*/fd`. The device in the title answered a question;
  the program whose discovery is silently broken is never the one the address
  points at. The same alerts on this machine were Chrome's Cast discovery in
  early August 2026 and Spotify three weeks later.
- **`discovery_replies` config key** — `quiet` (default, journal only) |
  `alert` | `ignore`.

### Changed

- Discovery-reply alerts are keyed on the protocol rather than the destination
  port. Each discovery round asks from a fresh ephemeral port, so port-keyed
  alerts made every round a brand-new subject — which is how one broken
  discovery loop produced a stack of popups rather than one.
- `Alert` gained a `popup` flag, separate from urgency. Urgency ranks alerts
  that all deserve the screen; some findings are true, worth recording, and
  still not events.

## [0.1.1] — 2026-08-19

A consumed UDP stream (Moonlight game streaming) was reported as "Unanswered
inbound traffic … Nothing on this host appears to be answering it." Fixed at
every layer it was wrong.

### Fixed

- **Unmeasured conntrack no longer reads as measured zero.** With
  `net.netfilter.nf_conntrack_acct` off, the kernel omits every byte counter,
  and the resulting zero was cited as proof that nothing consumed the traffic.
  `ss` reports no byte counters for UDP sockets, so conntrack was the only
  possible witness to a UDP stream — its blindness is now reported as "could
  not check", never as evidence.
- **The boot race that turned accounting off.** The sysctl path
  `/proc/sys/net/netfilter/nf_conntrack_acct` does not exist until the
  `nf_conntrack` module loads, which on a firewalled desktop happens *after*
  `systemd-sysctl` runs — so the setting was silently dropped on most boots.
  The collector installer now ships an `/etc/modules-load.d/` entry;
  `systemd-sysctl.service` is ordered after `systemd-modules-load.service`, so
  the setting applies deterministically.
- **Alerts weaken where they cannot verify — in the popup, not just the
  journal.** When UDP could not be checked, the notification now reads
  "Unverified inbound traffic … a video or game stream looks exactly like
  this" at normal urgency, instead of a critical accusation.
- **Alert text names only the corroboration sources that actually reported**,
  and no longer says "Sockets and conntrack together" when only one measured.
- **No rate is computed across a blind-to-measurable transition**, which
  understated consumption in exactly the direction that invents alerts.
- **An empty conntrack table is no longer misdiagnosed** as accounting being
  off, and no longer prescribes a sysctl that is already set.

### Known limitation

The kernel allocates byte counters only when a flow is created. Streams
established before accounting was enabled can never be measured and keep
alerting until they reconnect; correct from the next boot onward.

## [0.1.0] — 2026-08-07

First release.

packetminder notices inbound traffic **nothing on your host is consuming** —
the traffic that socket-oriented tools are structurally blind to — and raises
a desktop notification naming the device responsible.

### The daemon

- Six detectors at four layers: interface counter asymmetry (with socket and
  conntrack corroboration so a fast download is not mistaken for a flood),
  repeated firewall drops from one source, this host's own firewall-dropped
  traffic, datagrams delivered to ports with no listener, receive-queue
  overflow, and IPv6 addressing appearing where there was none.
- Role-aware: detects forwarding per interface and judges a hotspot or
  connection-sharing host at host scope, where per-interface asymmetry is what
  a *working* router looks like. Reports dual-homing.
- Devices named the way you know them: your own labels from the config, then
  a plausibly human hostname, then the vendor behind the MAC (via systemd's
  local hwdb — a Roku's `X01000EKSRNP.local` shows as "Roku"), then the bare
  address. Name resolution never stalls the detectors: alerts emit
  immediately and enrich in place.
- Notifications are two lines with an "Open packetminder" button that
  launches the TUI; full context goes to the journal, the only log.
- `--replay` re-runs the drop detector over real journal history at original
  timestamps — the honest way to tune thresholds. `--status` for a one-shot
  sample, `--selftest` to prove the notification path.
- Unprivileged, dependency-free, hardened systemd user service.

### The collector (optional)

A privilege-separated system service — a small audited script, not the
daemon — exports conntrack byte totals (closing the UDP/QUIC corroboration
gap) and exact firewall drop counters (which the rate-limited ufw log cannot
provide) to `/run/packetminder` for the unprivileged daemon to read.

### The TUI

`packetminder-tui`: a live table of TCP connections with per-connection
speeds, totals, and whois-resolved ISP names. Panic-safe terminal handling.

[0.1.1]: https://github.com/pizzimenti/packetminder/releases/tag/v0.1.1
[0.1.0]: https://github.com/pizzimenti/packetminder/releases/tag/v0.1.0

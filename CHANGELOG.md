# Changelog

All notable changes to packetminder are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and versions follow
[Semantic Versioning](https://semver.org/).

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

[0.1.0]: https://github.com/pizzimenti/packetminder/releases/tag/v0.1.0

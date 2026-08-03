# netwatch-alertd

A background service that notices inbound traffic **nothing on this host is
consuming**, and raises a desktop notification naming the source.

## Why this exists, separately from the TUI

`netwatch-core` polls `ss -tinH`. That is connection-oriented by construction,
so it can only ever show traffic that belongs to a socket. UDP aimed at a port
with no listener has no socket, no conntrack entry, no owning process, and no
row in `ss` — but it still fills the link.

That gap is not hypothetical. On 2026-08-03 a Sunshine host (caldera) kept
streaming video and audio at this machine after its Moonlight client had gone
away, at 2.7 Mbps, into two UDP ports nothing was bound to. `nethogs` showed
nothing, `ss` showed nothing, and the TUI showed an idle network — while the
desktop bandwidth widget showed a steady 3.7 Mibps download that nothing could
account for.

The reason it ran unnoticed for so long is worth stating plainly: **ufw `DROP`s
silently.** Sunshine's media path is unacknowledged RTP, so it depends entirely
on a control-channel timeout to notice a dead client. A `REJECT` would have
returned ICMP port-unreachable per packet and torn the session down in seconds.
A `DROP` gives the sender nothing at all, so it transmits into a black hole
indefinitely.

## What it watches

Two detectors, deliberately at different layers than the TUI:

| Detector | Source | Catches |
| --- | --- | --- |
| `asymmetric-inbound` | `/proc/net/dev` counters | Sustained inbound with near-zero outbound. A host that is genuinely downloading also sends — ACKs, QUIC acks, control traffic. Under 5% outbound means this host is not part of the conversation. |
| `blocked-flow` | kernel log, `[UFW BLOCK]` records | One source being dropped repeatedly for minutes, grouped by (source, protocol, destination port). Names the culprit exactly, and reports whether anything is actually listening on that port. |

The two cross-reference: an interface-level alert includes whatever the drop log
knows about who is responsible.

A `blocked-flow` alert distinguishes two very different situations:

- **Nothing listening** — someone is transmitting into the void. Tonight's case.
- **Something IS listening** — the firewall is blocking traffic a local service
  wants. This is how the service found, on its first run, that ufw was dropping
  Tailscale's IPv6 peer traffic to `udp/41641` and forcing a DERP relay fallback.

## Install

```sh
./install.sh
```

Builds release, installs to `~/.local/bin`, installs and starts the user unit,
and writes a commented default config on first run only. Safe to re-run.

## Use

```sh
netwatch-alertd --status          # one interface sample, with rates
netwatch-alertd --replay -24h     # what would have alerted over past history
netwatch-alertd --selftest        # prove the notification path works
journalctl --user -u netwatch-alertd -f
```

`--replay` is the honest way to tune thresholds. It re-runs the blocked-flow
detector over real journal history at the original timestamps, so you can point
it at a period when something was wrong, confirm it fires, then point it at a
normal day and confirm it stays quiet.

Note that ufw rate-limits its own logging, so drop *counts* understate reality
badly — tonight's 2.7 Mbps flood (roughly 500 packets/sec) produced only 34
log records. Counts indicate persistence, not volume.

## Config

`~/.config/netwatch/alertd.conf`, plain `key = value`, all keys optional. Read
at startup only; restart the service after editing.

Defaults: 1 Mbps inbound floor, 5% asymmetry ratio held for 60s, 4 drop records
spanning 2 minutes, 30-minute cooldown per subject.

Pointing `log_path` outside `~/.local/state/netwatch` requires relaxing
`ProtectHome=` in the unit.

## Privileges

None. It reads `/proc/net/*` and the journal, both available to a normal user
in a journal-reading group. It is dependency-free and does not link
`netwatch-core` — that crate is built with pyo3's `extension-module`, which
leaves libpython symbols undefined, which is fine for a cdylib and a link error
for a binary.

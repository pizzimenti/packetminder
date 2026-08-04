# netwatch

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
| `self-blocked` | the records `blocked-flow` rejects | Traffic *this host* sends that its own firewall drops. Not an attack, but not nothing — see below. |
| `ipv6-active` | `ip addr`, every 60s | IPv6 addressing appeared on an interface that had none. |

The two cross-reference: an interface-level alert includes whatever the drop log
knows about who is responsible.

Sources are named rather than numbered wherever they resolve —
`customer.sttlwax1.isp.starlink.com (2605:59ca:…)` rather than a bare address.
Lookups go through `getent`, so they use whatever nsswitch is configured with,
which on a desktop means mDNS and systemd-resolved's cache and not just unicast
PTR. The address is always kept alongside the name: a name alone is ambiguous
after a DHCP reshuffle, and the address is what you need in order to write a
firewall rule or start a capture. Results are cached for 5 minutes, negatives
included, so a LAN without reverse records does not pay a lookup on every tick.

Whether a source is a neighbour or a stranger is decided by **whether it shares
a prefix with one of this host's own addresses**, not by its address class.
Under IPv4 the two agree, because RFC1918 space is not routable. Under IPv6 they
do not: there is no NAT, so the machine on the next desk holds a globally
routable address, and asking whois about it returns a confident, correct, and
completely misleading answer naming whoever owns the allocation.

This is not hypothetical either. The `udp/41641` Tailscale drops below came from
`2605:59ca:3307:0c08:8255:…` and were reported as `internet, SpaceX Services,
Inc.` — while this host held `2605:59ca:3307:0c08:0db3:…` on the same /64. ufw
was forcing a DERP relay between two machines on the same switch, and the alert
described one of them as being on the far side of the internet.

Private v4 space is still consulted as a fallback, so a LAN host reached through
a router is classified correctly, and so is everything if `ip addr` fails.

A `blocked-flow` alert distinguishes two very different situations:

- **Nothing listening** — someone is transmitting into the void. Tonight's case.
- **Something IS listening** — the firewall is blocking traffic a local service
  wants. This is how the service found, on its first run, that ufw was dropping
  Tailscale's IPv6 peer traffic to `udp/41641` and forcing a DERP relay fallback.

## What it deliberately ignores

The blocked-flow detector answers exactly one question: *who is transmitting
into a port nothing is listening on?* Two classes of drop record cannot answer
it, and are discarded before the tracker ever sees them.

**Packets this host sent itself.** When a program sends multicast, the kernel
loops a copy back into `INPUT`, where a default-deny firewall drops and logs it.
`SRC` is one of our own addresses and there is no `MAC=` field, because the
packet never reached the wire.

**Packets addressed to a group** — `224.0.0.0/4`, `ff00::/8`, `255.255.255.255`,
and the subnet broadcast. LLMNR, mDNS, SSDP and NetBIOS shout at the whole
segment continuously, by design. A drop there means "this host did not
subscribe", not "this traffic was misdirected at this host".

Both filters exist because of a real false positive: on 2026-08-03 the service
fired a `critical` popup claiming `10.3.153.246 is flooding udp/5355`, where
`10.3.153.246` is this machine and `udp/5355` is systemd-resolved's own LLMNR
query looping back. Over the preceding 24 hours, 50 of 426 drop records were one
of these two cases and none of the 50 could have meant anything.

The filters are structural rather than a port list, which is why `ignore_ports`
defaults to empty and should usually stay that way. Note that they overlap on
purpose: this host's IPv6 LLMNR queries are caught as self-sourced while its
link-local address is assigned, and as group-addressed regardless.

## What it does with them instead

Filtering self-sourced records out of `blocked-flow` is right — nobody is
transmitting at this host. Discarding them would not be. Over 7 days, 361 of
4287 ufw records on this machine (8.4%) were locally generated, and that matters
for three reasons:

1. **It consumes the log budget.** ufw rate-limits its own logging, which is why
   a 2.7 Mbps flood produced 34 records. Every self-inflicted record is one a
   real event does not get.
2. **It proves the same traffic is blocked inbound.** The looped copy and a
   peer's reply take the same path. If mDNS discovery is meant to work here,
   this is how you find out it cannot.
3. **Some of it is genuinely wrong.** Benign loopback is *always* addressed to a
   multicast or broadcast group. Locally-sourced **unicast** arriving on the
   input path is a routing loop, a misconfigured tunnel, or a spoofed source.

So they go to a second detector, keyed on destination — the source is always us,
so it carries no information.

**The threshold counts distinct minutes with activity, not records.** That
distinction is the whole design. ufw's limiter caps records per minute, so a
record count measures the limiter more than the traffic; which minutes saw
activity survives it. systemd-resolved's LLMNR retries are three packets
followed by eight quiet minutes — active in roughly five minutes of any hour,
against a default threshold of 30. A program stuck in a retry loop is active in
nearly all sixty. Self-sourced unicast skips the threshold entirely and alerts
`critical` on 4 records, because no volume of it is normal.

Below the threshold, the counts still reach the event log hourly, so
sub-threshold self-traffic is visible rather than merely filtered.

One caveat specific to this detector: it depends on recognising this host's own
addresses, so on a machine that roams it under-reports in `--replay`. A 7-day
replay attributed only 16 records to this host against 361 that were actually
locally generated, because the rest arrived under addresses it no longer has.
Live operation re-reads every 60 seconds and gets it right.

## Watching IPv6

Every address test here — self-sourced, group-addressed, on-link — already
handles IPv6, and handles it as a first-class case rather than an afterthought:
addresses are compared parsed so the kernel's expanded form matches `ip`'s
compressed one, and `is_on_link` exists specifically because IPv6 has no NAT and
so no address-class shortcut. None of that depends on IPv6 being up when the
service starts; the address set is re-read every 60 seconds.

On top of that, `ipv6-active` reports when IPv6 addressing appears on an
interface that had none. It is a state change, not a judgement — equally useful
if you expect IPv6 and want to know when it arrived. Only appearances are
reported: addresses going away is an interface being reconfigured or unplugged,
which happens constantly on a machine that roams and says nothing about whether
IPv6 is enabled. Whatever is assigned at startup is seeded rather than announced,
so restarting the service is not an event. Set `watch_ipv6 = false` to disable.

The reason it exists: on this host, `/etc/sysctl.d/99-disable-ipv6.conf` has
disabled IPv6 since 2026-02-22, and IPv6 was nevertheless fully up on
`enp3s0f3u2` — with a routable Starlink `/64` — as recently as this morning.
**NetworkManager overrides the sysctl per interface.** A connection profile with
`ipv6.method=auto` clears `disable_ipv6` for its own interface when it
activates, and 66 of this machine's 82 saved profiles are set that way. Every
newly joined network adds another, because `auto` is the default and NM's
connection-defaults mechanism does not accept `ipv6.method` as an overridable
key. Anything short of `ipv6.disable=1` on the kernel command line is
whack-a-mole, so the tool assumes IPv6 can come back at any time.

`--replay` prints what it discarded and why, so a quiet result always reads as
"these were filtered on purpose" rather than as an unexplained absence.

One caveat, since it has now caused a wrong conclusion twice: **every judgement
that depends on this host's addresses is made against the addresses it has
right now.** The journal does not record what they were at the time. On a
machine whose interfaces flap — or whose IPv6 gets disabled between the event
and the replay — a historical record can be classified against an address set
that no longer resembles the one it arrived under. Live operation re-reads every
60 seconds and is fine; `--replay` cannot be.

## Install

```sh
./install.sh
```

Builds release, installs to `~/.local/bin`, installs and starts the user unit,
and writes a commented default config on first run only. Safe to re-run.

## Use

```sh
netwatch --status          # one interface sample, with rates
netwatch --replay -24h     # what would have alerted over past history
netwatch --selftest        # prove the notification path works
journalctl --user -u netwatch -f
```

`--replay` is the honest way to tune thresholds. It re-runs the blocked-flow
detector over real journal history at the original timestamps, so you can point
it at a period when something was wrong, confirm it fires, then point it at a
normal day and confirm it stays quiet.

Note that ufw rate-limits its own logging, so drop *counts* understate reality
badly — tonight's 2.7 Mbps flood (roughly 500 packets/sec) produced only 34
log records. Counts indicate persistence, not volume.

## Config

`~/.config/netwatch/netwatch.conf`, plain `key = value`, all keys optional. Read
at startup only; restart the service after editing.

Defaults: 1 Mbps inbound floor, 5% asymmetry ratio held for 60s, 4 drop records
spanning 2 minutes, 30-minute cooldown per subject, no ignored ports.

`ignore_ports` takes a comma-separated list and is parsed all-or-nothing — a
typo in one entry keeps the default rather than silently widening the blind
spot. Prefer leaving it empty; if a port is noisy, the reason is usually
something the structural filters above should be catching instead.

Pointing `log_path` outside `~/.local/state/netwatch` requires relaxing
`ProtectHome=` in the unit.

## Privileges

None. It reads `/proc/net/*` and the journal, both available to a normal user
in a journal-reading group. It is dependency-free and does not link
`netwatch-core` — that crate is built with pyo3's `extension-module`, which
leaves libpython symbols undefined, which is fine for a cdylib and a link error
for a binary.

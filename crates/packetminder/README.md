# packetminder

A background service that notices inbound traffic **nothing on this host is
consuming**, and raises a desktop notification naming the source.

## Why this exists, separately from the TUI

`packetminder-core` polls `ss -tinH`. That is connection-oriented by construction,
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

Detectors, deliberately at different layers than the TUI:

| Detector | Source | Catches |
| --- | --- | --- |
| `asymmetric-inbound` | `/proc/net/dev` counters | Sustained inbound with near-zero outbound. A host that is genuinely downloading also sends — ACKs, QUIC acks, control traffic. Bulk TCP runs ~2.2% outbound, so under 2% means this host is probably not part of the conversation. See the caveat below. |
| `blocked-flow` | kernel log, `[UFW BLOCK]` records | One source being dropped repeatedly for minutes, grouped by (source, protocol, destination port). Names the culprit exactly, and reports whether anything is actually listening on that port. |
| `self-blocked` | the records `blocked-flow` rejects | Traffic *this host* sends that its own firewall drops. Not an attack, but not nothing — see below. |
| `udp-no-listener` | `Udp.NoPorts`, `/proc/net/snmp` | Datagrams the kernel delivered to a port with no socket. The premise of this daemon, counted at the source — and unlike the drop log it covers traffic the firewall *allows* through to a dead port. |
| `receive-overflow` | `Udp.RcvbufErrors`, `TcpExt.ListenDrops` | Traffic dropped because a receive queue was full. The inverse problem: something *is* listening and cannot keep up. Invisible everywhere else, because from outside it looks like traffic being consumed. |
| `ipv6-active` | `ip addr`, every 60s | IPv6 addressing appeared on an interface that had none. |

The interface and drop-log detectors cross-reference: an interface-level alert
carries whatever the drop log currently knows, labelled as concurrent rather
than causal, since a handful of dropped packets cannot explain megabits.

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

Below the threshold, the counts still reach the journal hourly, so
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
packetminder --status          # one interface sample, with rates
packetminder --replay -24h     # what would have alerted over past history
packetminder --selftest        # prove the notification path works
journalctl --user -u packetminder -f
```

`--replay` is the honest way to tune thresholds. It re-runs the blocked-flow
detector over real journal history at the original timestamps, so you can point
it at a period when something was wrong, confirm it fires, then point it at a
normal day and confirm it stays quiet.

Note that ufw rate-limits its own logging, so drop *counts* understate reality
badly — tonight's 2.7 Mbps flood (roughly 500 packets/sec) produced only 34
log records. Counts indicate persistence, not volume.

### Do not raise the log limit to fix that

The limiter is `-m limit --limit 3/min --limit-burst 10` on the `LOG` rule in
`ufw-after-logging-input`. Raising it is the obvious move and the wrong one.

ufw offers no level that unrate-limits blocked-packet logging on its own: per
`man ufw`, `high` is "medium **without rate limiting**, plus all packets with
rate limiting", so buying accurate drop counts also buys a log line for allowed
traffic. On a host doing 98 Mbps that is not a tradeoff worth making.

The volume the log cannot give you is already recorded exactly, for free, with
no logging at all — every firewall rule carries a packet and byte counter:

```sh
sudo iptables -L ufw-after-input -v -n -x      # what reached the drop path
sudo iptables -L INPUT -v -n -x | head -3      # policy DROP totals
```

Measured on this host at 7.5 hours uptime: the `LOG` rule had emitted 1212
records, against a theoretical ceiling of ~1350 for `3/min` over that period.
The count was set by the limiter, not by the traffic — which is the whole point.
The policy `DROP` counter meanwhile read 1835 packets / 643,506 bytes, exactly,
and a further 3388 broadcast packets were dropped via `ufw-skip-to-policy-input`
without ever reaching a logging rule at all.

So: the log is for **identity** — who, which port, how persistently — and 1212
samples name a culprit perfectly well. The counters are for **volume**. Asking
the log for volume is asking the wrong source, and no amount of raising the
limit changes that.

## Config

`~/.config/packetminder/packetminder.conf`, plain `key = value`, all keys optional. Read
at startup only; restart the service after editing.

Defaults: 1 Mbps inbound floor, 2% asymmetry ratio held for 60s, 4 drop records
spanning 2 minutes, 30-minute cooldown per subject, no ignored ports.

### The asymmetry ratio cannot be exact

Bulk TCP with delayed ACKs sends about one 66-byte ack per two 1514-byte
frames, so a healthy download already runs near 2.2% outbound. The original 5%
default therefore fired on ordinary large downloads: an observed alert here
reported 35.21 Mbps at 1.8%, which is what a fast download looks like, not an
attack.

2% sits just below the ACK floor, which narrows the overlap without closing it.
Large-receive-offload can push a real download under 2%, and a genuinely
one-sided flood can carry a little back-chatter. Separating them properly means
asking whether an established socket accounts for the volume, rather than
tuning a ratio.

`ignore_ports` takes a comma-separated list and is parsed all-or-nothing — a
typo in one entry keeps the default rather than silently widening the blind
spot. Prefer leaving it empty; if a port is noisy, the reason is usually
something the structural filters above should be catching instead.

### Naming devices

```
name a8:b5:7c:53:b2:fe = Roku
name 10.3.59.7         = caldera
```

Repeatable, and consulted before any lookup. This exists because discovery can
only ever report what a device is, not which one it is. An OUI gives the type,
so two identical travel routers are both `GL`; mDNS gives whatever the firmware
publishes, which for consumer hardware is frequently a serial number like
`X01000EKSRNP.local`.

Key on a MAC to survive a DHCP reshuffle, or on an address for devices that
never appear in the neighbour table. Resolution order is: your name, then a
hostname that looks like a person chose it, then the vendor behind the MAC,
then the bare address.

## Logs

The journal, and only the journal:

```sh
journalctl --user -u packetminder -f        # follow
journalctl --user -u packetminder -S -7d    # last week
```

There is no second log file. systemd already timestamps, rotates and caps what
it stores, and every alert is written to stderr, so a hand-rolled copy on disk
was a duplicate that could grow without bound. The daemon writes nothing to
disk at all now, which is why the unit needs no `StateDirectory=`.

Retention is journald's, set in `/etc/systemd/journald.conf.d/limits.conf`
(`SystemMaxUse=200M`, currently about three weeks of history on this machine).

## The collector (optional, privileged)

Two things this daemon wants are root-only: conntrack byte counters and exact
firewall drop totals. Rather than run the whole daemon as root, `collector/`
installs a small system service that reads exactly those two and writes them to
`/run/packetminder/snapshot`, world-readable.

```sh
sudo crates/packetminder/collector/install-collector.sh
```

The split matters. packetminder parses input that hostile hosts influence — kernel
log lines carrying attacker-chosen addresses, mDNS names any LAN device can
publish, whois answers from remote servers — and shells out with data derived
from them. Running that as root would turn a parsing slip into a root
compromise, sourced from the very hosts it is watching. The collector instead
parses nothing from the network, opens no connections, notifies nobody, and
runs with a capability bounding set of exactly `CAP_NET_ADMIN` and
`CAP_DAC_READ_SEARCH`.

It closes the two gaps documented above:

| gap | closed by |
| --- | --- |
| `ss` has no byte counters for UDP, so QUIC transfers cannot be corroborated | conntrack tracks UDP flows. Measured at 99% of a 61.8 MB UDP transfer. |
| the ufw log is rate limited, so drop counts measure the limiter | `input_drop_packets` / `input_drop_bytes`, exact |

Two implementation notes worth knowing, both found by testing rather than
reasoning:

**Summing the live conntrack table is a gauge, not a counter.** Each entry holds
bytes-so-far for a flow that eventually expires and is removed, so the total
*falls* when a large flow ages out — a 94 MB upload right after a 98 MB download
produced a delta of minus 97 MB. The collector therefore accumulates positive
per-flow increments across expiries instead, yielding a monotonic figure.

**`nf_conntrack_acct` only attaches counters to flows created after it is
enabled.** Pre-existing flows stay uncounted permanently, which is why the
installer writes `/etc/sysctl.d/99-packetminder-conntrack-acct.conf` rather than
setting it at runtime. Expect partial coverage until flows turn over.

## Privileges

None. It reads `/proc/net/*` and the journal, both available to a normal user
in a journal-reading group.

It is dependency-free on purpose: it parses input that hostile hosts influence,
so the smaller its supply chain the better. See *The collector* above for the
same reasoning applied to privilege.

It also does not link `packetminder-core`, though that is now a choice rather than a
constraint. Core used to be built with pyo3's `extension-module`, which left
libpython symbols undefined — fine for a cdylib, a link error for a binary. The
Python binding and the Qt app that used it are gone, so core is a plain rlib and
this *could* link it. It still should not: core polls `ss` to describe
connections, which is precisely the question this daemon exists because nothing
could answer.

# packetminder

Tools for noticing network traffic that connection-oriented tools structurally
cannot see.

`ss`, `nethogs`, and every socket-enumerating monitor answer "what are my
connections doing?" — which is only the whole picture if all traffic belongs to
a connection. It doesn't: UDP aimed at a port with no listener has no socket,
no conntrack entry, and no owning process, yet it still fills the link. This
repo exists because a media server once streamed 2.7 Mbps at a machine for
hours while every conventional tool showed an idle network.

## Components

| component | what it is |
| --- | --- |
| [`crates/packetminder`](crates/packetminder/) | The daemon. Watches interface counters, kernel drop records, and protocol counters for traffic nothing is consuming, and raises desktop notifications naming the device responsible. Dependency-free, unprivileged, runs as a systemd user service. **Start with its [README](crates/packetminder/README.md).** |
| [`crates/packetminder/collector`](crates/packetminder/collector/) | Optional privileged half: a 60-line script that exports conntrack byte totals and exact firewall drop counters to `/run`, so the daemon can stay unprivileged. |
| [`crates/packetminder-tui`](crates/packetminder-tui/) | Interactive terminal viewer for live TCP connections — the "what are my connections doing?" side, for when the daemon's alert points you at something worth watching. |
| [`crates/packetminder-core`](crates/packetminder-core/) | Shared connection-polling library behind the TUI. |

## Quick start

```sh
crates/packetminder/install.sh                        # daemon + TUI, user service
sudo crates/packetminder/collector/install-collector.sh   # optional, closes the UDP/QUIC gap
```

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your
option.

#!/usr/bin/env bash
# Build packetminder and install it as a systemd user service.
#
# Safe to re-run: it rebuilds, reinstalls, and restarts, which is how you pick
# up code or unit changes.

set -euo pipefail

crate_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$crate_dir/../.." && pwd)"

bin_dir="$HOME/.local/bin"
unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/packetminder"
unit_name="packetminder.service"

echo "==> Building (release)"
# The TUI comes too: an alert's "Open packetminder" button launches it, and a
# button that cannot work is worse than no button.
cargo build --release --manifest-path "$repo_dir/Cargo.toml" -p packetminder -p packetminder-tui

echo "==> Installing binaries to $bin_dir"
install -Dm755 "$repo_dir/target/release/packetminder" "$bin_dir/packetminder"
install -Dm755 "$repo_dir/target/release/packetminder-tui" "$bin_dir/packetminder-tui"

echo "==> Installing unit to $unit_dir"
install -Dm644 "$crate_dir/$unit_name" "$unit_dir/$unit_name"

# Never clobber a config the user has tuned.
if [[ ! -f "$config_dir/packetminder.conf" ]]; then
    echo "==> Writing default config to $config_dir/packetminder.conf"
    install -d "$config_dir"
    cat >"$config_dir/packetminder.conf" <<'EOF'
# packetminder configuration. Every key is optional.
# Re-read at start only: restart the service after editing.
#   systemctl --user restart packetminder

# -- Sampling --
# interval_secs = 10

# -- Asymmetry detector --
# Inbound traffic this fast (bits/sec) with almost no outbound means this host
# is receiving something it is not part of.
# Bulk TCP acks at roughly 2.2% of the inbound rate, so this sits just below
# that. Raising it above ~0.03 will alert on ordinary large downloads.
# rx_floor_bps = 1000000
# asym_ratio = 0.02
# asym_sustain_secs = 60
# ignore_interfaces = lo, tailscale0

# -- Firewall-drop detector --
# block_pattern = UFW BLOCK
# block_min_events = 4
# block_window_secs = 900
# block_min_span_secs = 120
#
# Destination ports to discard outright. Usually unnecessary and best left
# empty: drops this host sent itself, and drops addressed to a multicast or
# broadcast group, are already filtered structurally. Parsed all-or-nothing,
# so a typo keeps the default rather than widening the blind spot.
# ignore_ports = 5355, 5353

# -- Self-blocked detector --
# Traffic this host sends that its own firewall drops. Thresholded on how many
# distinct minutes of the window saw activity, not on how many records were
# logged -- ufw rate-limits its own logging, so a record count measures the
# limiter more than the traffic.
# self_window_secs = 3600
# self_min_active_minutes = 30
#
# Locally-sourced unicast on the input path has no benign explanation, so it
# alerts on this many records regardless of the window.
# self_unicast_min_events = 4

# -- IPv6 watch --
# Report when IPv6 addressing appears on an interface that had none. A state
# change, not a judgement -- useful whether you want IPv6 off and need to know
# it came back, or expect it and want to know when it arrived.
# watch_ipv6 = true

# -- Protocol counters --
# Watches /proc/net/snmp and /proc/net/netstat, which see two things the other
# detectors cannot: datagrams the firewall ALLOWS through to a port with no
# socket, and traffic this host wanted but could not drain fast enough.
# watch_proto = true
#
# Datagrams/sec delivered to a port nothing is bound to (Udp.NoPorts).
# noports_min_rate = 5
#
# Packets/sec dropped because a receive queue was full (Udp.RcvbufErrors plus
# TcpExt.ListenDrops/ListenOverflows). This one means a local program is too
# slow or its buffer too small -- the traffic was wanted.
# rcvbuf_min_rate = 10
#
# proto_sustain_secs = 60

# -- Device names --
# What you call your devices. Repeatable, and consulted before any lookup.
# Key on a MAC to survive DHCP reshuffles, or on an address for devices that
# never appear in the neighbour table. Without this an alert can only report
# what it can discover: a vendor OUI gives the device *type*, so two identical
# travel routers are both "GL", and mDNS gives whatever the firmware publishes,
# which is often a serial number.
#
# name a8:b5:7c:53:b2:fe = Roku
# name 10.3.59.7         = caldera

# -- Output --
# cooldown_secs = 1800
# notify = true
#
# Alerts carry an "Open packetminder" button that launches the TUI. Left empty this
# finds a terminal emulator and runs packetminder-tui in it. Set an explicit command
# to override, or "off" to drop the button. Split on whitespace, not a shell.
# tui_command = konsole -e packetminder-tui
EOF
else
    echo "==> Keeping existing config at $config_dir/packetminder.conf"
fi

echo "==> Verifying unit"
# Verify resolves %h/%S specifiers against the real user manager.
systemd-analyze --user verify "$unit_dir/$unit_name"

echo "==> Reloading and restarting"
systemctl --user daemon-reload
systemctl --user enable "$unit_name" >/dev/null
systemctl --user restart "$unit_name"

echo
systemctl --user --no-pager --lines=0 status "$unit_name" || true
echo
echo "Installed. Useful commands:"
echo "  systemctl --user status packetminder"
echo "  journalctl --user -u packetminder -f"
echo "  packetminder --status          # one interface sample"
echo "  packetminder --replay -24h     # what would have alerted"
echo "  packetminder --selftest        # prove notifications work"

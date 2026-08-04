#!/usr/bin/env bash
# Build netwatch-alertd and install it as a systemd user service.
#
# Safe to re-run: it rebuilds, reinstalls, and restarts, which is how you pick
# up code or unit changes.

set -euo pipefail

crate_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$crate_dir/../.." && pwd)"

bin_dir="$HOME/.local/bin"
unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/netwatch"
unit_name="netwatch-alertd.service"

echo "==> Building (release)"
cargo build --release --manifest-path "$repo_dir/Cargo.toml" -p netwatch-alertd

echo "==> Installing binary to $bin_dir"
install -Dm755 "$repo_dir/target/release/netwatch-alertd" "$bin_dir/netwatch-alertd"

echo "==> Installing unit to $unit_dir"
install -Dm644 "$crate_dir/$unit_name" "$unit_dir/$unit_name"

# Never clobber a config the user has tuned.
if [[ ! -f "$config_dir/alertd.conf" ]]; then
    echo "==> Writing default config to $config_dir/alertd.conf"
    install -d "$config_dir"
    cat >"$config_dir/alertd.conf" <<'EOF'
# netwatch-alertd configuration. Every key is optional.
# Re-read at start only: restart the service after editing.
#   systemctl --user restart netwatch-alertd

# -- Sampling --
# interval_secs = 10

# -- Asymmetry detector --
# Inbound traffic this fast (bits/sec) with almost no outbound means this host
# is receiving something it is not part of.
# rx_floor_bps = 1000000
# asym_ratio = 0.05
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

# -- Output --
# cooldown_secs = 1800
# notify = true
EOF
else
    echo "==> Keeping existing config at $config_dir/alertd.conf"
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
echo "  systemctl --user status netwatch-alertd"
echo "  journalctl --user -u netwatch-alertd -f"
echo "  netwatch-alertd --status          # one interface sample"
echo "  netwatch-alertd --replay -24h     # what would have alerted"
echo "  netwatch-alertd --selftest        # prove notifications work"

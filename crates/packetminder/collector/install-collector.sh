#!/usr/bin/env bash
# Install the privileged collector. Run as root; the daemon itself is installed
# separately by ../install.sh and stays unprivileged.
#
# Safe to re-run. To remove everything this installs, see the bottom of the
# file.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This installs a system service and must run as root:" >&2
    echo "  sudo $0" >&2
    exit 1
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Installing collector to /usr/local/libexec"
install -Dm755 "$here/packetminder-collect" /usr/local/libexec/packetminder-collect

echo "==> Installing units to /etc/systemd/system"
install -Dm644 "$here/packetminder-collector.service" /etc/systemd/system/packetminder-collector.service
install -Dm644 "$here/packetminder-collector.timer" /etc/systemd/system/packetminder-collector.timer

# Without accounting every conntrack bytes= field reads zero, which silently
# turns the QUIC corroboration this exists for into "nothing is consuming
# anything". Cheap, but not free: the kernel maintains two extra counters per
# tracked flow.
#
# The sysctl alone is not enough, and fails in a way nothing surfaces:
# /proc/sys/net/netfilter/nf_conntrack_acct does not exist until nf_conntrack is
# loaded, and nothing loads it early -- on a firewalled desktop it arrives with
# the firewall's first conntrack rule, racing systemd-sysctl.service. When
# sysctl wins, the setting is dropped with one ignorable log line:
#
#   systemd-sysctl[408]: Couldn't write '1' to 'net/netfilter/nf_conntrack_acct',
#                        ignoring: No such file or directory
#
# and accounting stays off for the whole boot while everything looks installed
# and healthy. Forcing the module load fixes it for good: systemd-sysctl.service
# is ordered After=systemd-modules-load.service, so the path is guaranteed to
# exist by the time the setting is applied.
echo "==> Loading nf_conntrack early (so the sysctl below has somewhere to land)"
install -Dm644 /dev/stdin /etc/modules-load.d/packetminder-conntrack.conf <<'EOF'
# Ordered before systemd-sysctl, which is what makes
# /etc/sysctl.d/99-packetminder-conntrack-acct.conf apply at boot rather than
# being dropped as a nonexistent path.
nf_conntrack
EOF
modprobe nf_conntrack 2>/dev/null || true

echo "==> Enabling conntrack byte accounting"
install -Dm644 /dev/stdin /etc/sysctl.d/99-packetminder-conntrack-acct.conf <<'EOF'
# Required by packetminder-collector: without it /proc/net/nf_conntrack reports
# bytes=0 for every flow, and packetminder cannot tell a consumed transfer from an
# unconsumed one over UDP.
net.netfilter.nf_conntrack_acct = 1
EOF
sysctl --quiet --system

echo "==> Starting timer"
systemctl daemon-reload
systemctl enable --now packetminder-collector.timer >/dev/null
systemctl start packetminder-collector.service

echo
echo "Snapshot:"
sed 's/^/  /' /run/packetminder/snapshot 2>/dev/null || echo "  (not written yet)"
echo
echo "To remove:"
echo "  systemctl disable --now packetminder-collector.timer"
echo "  rm /etc/systemd/system/packetminder-collector.{service,timer}"
echo "  rm /usr/local/libexec/packetminder-collect"
echo "  rm /etc/sysctl.d/99-packetminder-conntrack-acct.conf"
echo "  rm /etc/modules-load.d/packetminder-conntrack.conf"
echo "  systemctl daemon-reload"

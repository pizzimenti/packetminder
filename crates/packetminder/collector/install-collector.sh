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
echo "  systemctl daemon-reload"

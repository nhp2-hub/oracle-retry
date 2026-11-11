#!/bin/bash
# Only allow SSH over Tailscale (blocks SSH from the public internet). Safe to re-run.
set -euo pipefail
RULES=/etc/iptables/rules.v4
OPEN='-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT'
TS='-A INPUT -i tailscale0 -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT'

echo "== 1/3 safety check: Tailscale must be up"
tailscale status >/dev/null 2>&1 || { echo "ERROR: Tailscale isn't running - not locking down (you'd be locked out)"; exit 1; }
ip addr show tailscale0 >/dev/null 2>&1 || { echo "ERROR: no tailscale0 interface - not locking down"; exit 1; }

echo "== 2/3 firewall: SSH only on tailscale0"
# live rules (current SSH session stays up via the ESTABLISHED rule)
sudo iptables -C INPUT -i tailscale0 -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT 2>/dev/null \
  || sudo iptables -I INPUT 1 -i tailscale0 -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
while sudo iptables -D INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT 2>/dev/null; do :; done

echo "== 3/3 make it stick after reboots"
if sudo grep -qxF -- "$TS" "$RULES"; then
  sudo sed -i "\|^${OPEN}\$|d" "$RULES"
elif sudo grep -qxF -- "$OPEN" "$RULES"; then
  sudo sed -i "s|^${OPEN}\$|${TS}|" "$RULES"
else
  echo "WARNING: couldn't find the SSH rule in $RULES - live rules changed, but may reset on reboot"
fi
echo "== done"
sudo iptables -S INPUT | grep -E 'dport 22' | sed 's/^/rule: /'
sudo grep -E 'dport 22' "$RULES" | sed 's/^/saved: /'

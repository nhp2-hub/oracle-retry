#!/bin/bash
# Full control for when the panel's 4 buttons aren't enough: installs Cockpit (web admin panel
# with a terminal, services and logs) and makes it reachable ONLY from your own Tailscale devices:
#     https://vex-micro.<your-tailnet>.ts.net:9090
# - Cockpit listens on 127.0.0.1 only; "tailscale serve" (NOT Funnel) passes it to the tailnet.
#   Funnel can't use port 9090 at all, so this can't end up on the public internet by accident.
# - It only uses RAM while you have it open (socket-activated).
# - Cockpit logs in with a Linux password, so this asks you to set one for this user (once).
#   SSH keeps refusing passwords (key only), and the script checks that.
# Run it by hand over SSH (it needs to ask for the password). Safe to re-run:
#   curl -fsSL https://raw.githubusercontent.com/nhp2-hub/oracle-retry/main/server/cockpit.sh | bash
# Remove it again:  sudo tailscale serve --https=9090 off && sudo apt-get purge -y cockpit-ws cockpit-bridge cockpit-system
set -euo pipefail

main() {
  echo "== 1/5 checks"
  local HOST
  HOST=$(tailscale status --json </dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"]["DNSName"].rstrip("."))' 2>/dev/null || true)
  [ -n "$HOST" ] || { echo "ERROR: Tailscale isn't running - not installing (Cockpit would have no safe way in)"; return 1; }
  # passwords must never work over SSH once this user has one
  if ! sudo sshd -T 2>/dev/null | grep -qi '^passwordauthentication no'; then
    echo "PasswordAuthentication no" | sudo tee /etc/ssh/sshd_config.d/00-vex1-no-passwords.conf >/dev/null
    sudo systemctl reload ssh
    sudo sshd -T 2>/dev/null | grep -qi '^passwordauthentication no' \
      || { echo "ERROR: couldn't turn off SSH password logins - stopping before setting a password"; return 1; }
    echo "== turned off SSH password logins (keys only)"
  else
    echo "== SSH is key-only (good)"
  fi

  echo "== 2/5 installing Cockpit (small version: no extras)"
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq </dev/null
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    cockpit-ws cockpit-bridge cockpit-system </dev/null >/dev/null

  echo "== 3/5 locking it to this machine + Tailscale"
  sudo mkdir -p /etc/systemd/system/cockpit.socket.d /etc/cockpit
  sudo tee /etc/systemd/system/cockpit.socket.d/listen.conf >/dev/null <<EOF
[Socket]
ListenStream=
ListenStream=127.0.0.1:9090
EOF
  sudo tee /etc/cockpit/cockpit.conf >/dev/null <<EOF
[WebService]
Origins = https://$HOST:9090 wss://$HOST:9090
LoginTo = false
[Session]
IdleTimeout = 15
EOF
  sudo systemctl daemon-reload
  sudo systemctl enable cockpit.socket >/dev/null 2>&1
  sudo systemctl restart cockpit.socket
  sudo tailscale serve --bg --https=9090 https+insecure://127.0.0.1:9090 </dev/null >/dev/null

  echo "== 4/5 password for $USER (Cockpit's login)"
  if sudo passwd -S "$USER" | awk '{exit !($2=="P")}' && [ "${NEW_PASSWORD:-}" != 1 ]; then
    echo "== $USER already has a password (run with NEW_PASSWORD=1 to change it)"
  else
    echo "Pick a password for Cockpit (you'll type it twice, it won't show):" >/dev/tty
    sudo passwd "$USER" </dev/tty >/dev/tty 2>&1 || { echo "ERROR: password not set - run this again"; return 1; }
  fi

  echo "== 5/5 testing"
  local CODE
  CODE=$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:9090/ </dev/null || true)
  [ "$CODE" = 200 ] || { echo "ERROR: Cockpit didn't answer (HTTP $CODE)"; sudo journalctl -u cockpit -n 10 --no-pager | sed 's/^/ERROR: /'; return 1; }
  if ss -ltn 2>/dev/null | grep ':9090 ' | grep -qv '127.0.0.1:9090'; then
    echo "WARNING: something besides 127.0.0.1 is listening on 9090 - check 'ss -ltn'"
  fi
  if tailscale funnel status 2>/dev/null </dev/null | grep -E ':9090 +\(' | grep -qi 'funnel on'; then
    echo "ERROR: Funnel is on for 9090 - turning this off"; sudo tailscale serve --https=9090 off </dev/null; return 1
  fi
  tailscale funnel status 2>/dev/null </dev/null | grep -q 8765 || echo "WARNING: the 8765 Funnel (connector) isn't showing - run: sudo tailscale funnel --bg 8765"
  echo "== done: open https://$HOST:9090 on a device that's on your Tailscale (user: $USER)"
}

main "$@"

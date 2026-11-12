#!/bin/bash
# NOTE: this runs via "bash -s" over SSH, so everything is wrapped in main() - otherwise
# curl/pip/systemctl can eat the rest of the script from stdin.
# Installs the status page + phone alerts on vex-micro. Safe to re-run.
#  - updates the connector code and restarts it (status page at /<token>/status, panel at /<token>/panel)
#  - lets the panel's 4 buttons work: a polkit rule that allows this user to start exactly
#    vex1-sync, the two vex1-kick jobs, and restart vex1-mcp. Nothing else.
#  - makes a secret ntfy topic (once) in ~/vex1-mcp/ntfy - shown on the status page, never in logs
#  - vex1-status-alert.timer checks everything every 5 min and pings the phone on changes
set -euo pipefail

main() {
  local DIR="$HOME/vex1-mcp" RAW="https://raw.githubusercontent.com/nhp2-hub/oracle-retry/main/server"
  [ -x "$DIR/venv/bin/python" ] || { echo "ERROR: run the mcp step first"; return 1; }

  echo "== 1/5 updating connector + status + panel code"
  curl -fsSL "$RAW/vex1_mcp.py" -o "$DIR/vex1_mcp.py" </dev/null
  curl -fsSL "$RAW/vex1_status.py" -o "$DIR/vex1_status.py" </dev/null
  curl -fsSL "$RAW/vex1_stream.py" -o "$DIR/vex1_stream.py" </dev/null
  curl -fsSL "$RAW/vex1_panel.py" -o "$DIR/vex1_panel.py" </dev/null
  curl -fsSL "$RAW/vex1_panel.html" -o "$DIR/vex1_panel.html" </dev/null
  "$DIR/venv/bin/pip" install -q "mcp<2" </dev/null

  echo "== 2/5 alert topic"
  if [ ! -s "$DIR/ntfy" ]; then
    ( umask 077; echo "NTFY_TOPIC=vex1-$(python3 -c 'import secrets;print(secrets.token_hex(12))')" > "$DIR/ntfy" )
    echo "== made a new alert topic (it's shown at the bottom of the status page)"
  else
    echo "== kept the existing alert topic"
  fi

  echo "== 3/5 5-minute self-check"
  sudo tee /etc/systemd/system/vex1-status-alert.service >/dev/null <<EOF
[Unit]
Description=Vex1 health check + phone alerts
After=network-online.target
[Service]
Type=oneshot
User=$USER
EnvironmentFile=$DIR/env
EnvironmentFile=$DIR/ntfy
Environment=VAULT=$HOME/vex1
StateDirectory=vex1-status
ExecStart=/usr/bin/python3 $DIR/vex1_status.py --alert
TimeoutStartSec=120
Nice=10
EOF
  sudo tee /etc/systemd/system/vex1-status-alert.timer >/dev/null <<EOF
[Unit]
Description=Vex1 health check every 5 minutes
[Timer]
OnBootSec=3min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
EOF
  echo "== 4/5 panel buttons (polkit rule)"
  if ! command -v pkaction >/dev/null 2>&1; then
    sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq </dev/null
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq polkitd </dev/null >/dev/null
  fi
  # The panel runs as $USER with no sudo. This lets $USER do these 4 unit actions and nothing more.
  sudo mkdir -p /etc/polkit-1/rules.d
  sudo tee /etc/polkit-1/rules.d/49-vex1-panel.rules >/dev/null <<EOF
polkit.addRule(function(action, subject) {
  if (action.id != "org.freedesktop.systemd1.manage-units" || subject.user != "$USER") return;
  var allowed = {
    "vex1-sync.service": "start",
    "vex1-kick@oracle-a1-retry.service": "start",
    "vex1-kick@watchdog.service": "start",
    "vex1-mcp.service": "restart"
  };
  if (allowed[action.lookup("unit")] == action.lookup("verb")) return polkit.Result.YES;
});
EOF
  sudo chmod 644 /etc/polkit-1/rules.d/49-vex1-panel.rules

  sudo systemctl daemon-reload
  sudo systemctl enable --now vex1-status-alert.timer >/dev/null 2>&1
  sudo systemctl restart vex1-mcp

  echo "== 5/5 testing"
  local TOKEN CODE=000
  TOKEN=$(cut -d= -f2- "$DIR/env")
  for _ in $(seq 1 40); do
    CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8765/$TOKEN/status" </dev/null || true)
    [ "$CODE" = 200 ] && break
    sleep 2
  done
  [ "$CODE" = 200 ] || { echo "ERROR: status page didn't load (HTTP $CODE)"; sudo journalctl -u vex1-mcp -n 15 --no-pager | sed 's/^/ERROR: /'; return 1; }
  echo "== status page OK"
  CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8765/$TOKEN/panel" </dev/null || true)
  if [ "$CODE" = 200 ]; then echo "== panel OK (same link as the status page, with /panel on the end)"; else echo "WARNING: panel didn't load (HTTP $CODE)"; fi
  # no sudo on purpose: this is exactly what the "Sync vault now" button does
  if systemctl start --no-block --no-ask-password vex1-sync.service </dev/null 2>/dev/null; then
    echo "== panel buttons OK"
  else
    echo "WARNING: panel buttons aren't allowed yet (polkit said no) - the rest of the panel still works"
  fi
  set -a; . "$DIR/env"; . "$DIR/ntfy"; set +a
  if python3 "$DIR/vex1_status.py" --test-alert </dev/null >/dev/null; then
    echo "== test alert sent"
  else
    echo "WARNING: couldn't send the test alert"
  fi
  VAULT="$HOME/vex1" python3 "$DIR/vex1_status.py" </dev/null | sed -n 1p | sed 's/^/== /'
  echo "== done"
}

main "$@"

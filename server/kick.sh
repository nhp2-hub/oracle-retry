#!/bin/bash
# Makes vex-micro start the A1 retry (every 15 min) and the Watchdog (every 30 min)
# on GitHub, because GitHub stopped running this repo's schedules. Safe to re-run.
# Asks once for a GitHub token (fine-grained, only oracle-retry, Actions: read & write).
set -euo pipefail

main() {
  local DIR="$HOME/vex1-mcp" RAW="https://raw.githubusercontent.com/nhp2-hub/oracle-retry/main/server"
  mkdir -p "$DIR"
  echo "== 1/4 getting the kick script"
  curl -fsSL "$RAW/vex1_kick.py" -o "$DIR/vex1_kick.py" </dev/null

  echo "== 2/4 GitHub token"
  if [ -s "$DIR/gh-kick" ] && [ "${NEW_TOKEN:-}" != 1 ]; then
    echo "== kept the saved token (run with NEW_TOKEN=1 to replace it)"
  else
    local TOKEN=""
    printf "Paste the GitHub token (it won't show), then press Enter: " >/dev/tty
    read -r -s TOKEN </dev/tty; echo >/dev/tty
    [ -n "$TOKEN" ] || { echo "ERROR: no token pasted"; return 1; }
    ( umask 077; echo "GH_KICK_TOKEN=$TOKEN" > "$DIR/gh-kick" )
    echo "== token saved (only you can read it)"
  fi

  echo "== 3/4 timers"
  sudo tee /etc/systemd/system/vex1-kick@.service >/dev/null <<UNIT
[Unit]
Description=Start GitHub workflow %i
After=network-online.target
[Service]
Type=oneshot
User=$USER
EnvironmentFile=$DIR/gh-kick
ExecStart=/usr/bin/python3 $DIR/vex1_kick.py %i.yml 10
UNIT
  sudo tee /etc/systemd/system/vex1-kick@oracle-a1-retry.timer >/dev/null <<UNIT
[Unit]
Description=A1 retry every 15 min
[Timer]
OnCalendar=*:02,17,32,47
Persistent=true
[Install]
WantedBy=timers.target
UNIT
  sudo tee /etc/systemd/system/vex1-kick@watchdog.timer >/dev/null <<UNIT
[Unit]
Description=Watchdog every 30 min
[Timer]
OnCalendar=*:07,37
Persistent=true
[Install]
WantedBy=timers.target
UNIT
  sudo systemctl daemon-reload
  sudo systemctl enable --now vex1-kick@oracle-a1-retry.timer vex1-kick@watchdog.timer >/dev/null 2>&1

  echo "== 4/4 testing the token"
  set -a; . "$DIR/gh-kick"; set +a
  if python3 - <<'PY' </dev/null
import os, json, urllib.request
r = urllib.request.Request("https://api.github.com/repos/nhp2-hub/oracle-retry/actions/workflows",
    headers={"Authorization": "Bearer " + os.environ["GH_KICK_TOKEN"], "User-Agent": "vex1-kick"})
print("== token works: sees", json.load(urllib.request.urlopen(r, timeout=20))["total_count"], "workflows")
PY
  then
    systemctl list-timers 'vex1-kick@*' --no-pager | sed -n '2,3p' | awk '{print "== next:", $NF, "at", $2, $3}'
    echo "== done"
  else
    echo "ERROR: GitHub didn't accept that token - make a new one and run the setup again with NEW_TOKEN=1 in front of bash"
    return 1
  fi
}

main "$@"

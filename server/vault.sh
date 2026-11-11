#!/bin/bash
# Clones Vex1 onto the server and keeps it synced from GitHub every 5 min. Safe to re-run.
set -euo pipefail
DIR="$HOME/vex1"
echo "== 1/3 check GitHub access"
ssh -o StrictHostKeyChecking=accept-new -T github-vex1 2>&1 | grep -q 'successfully authenticated' \
  || { echo "ERROR: GitHub doesn't accept the server's deploy key yet - add it to Vex1 first"; exit 1; }

echo "== 2/3 get the vault (first time is slow - ~2 GB on a Micro)"
if [ ! -d "$DIR/.git" ]; then
  git clone -q --depth 1 git@github-vex1:nhp2-hub/Vex1.git "$DIR"
else
  git -C "$DIR" pull -q --ff-only
fi

echo "== 3/3 auto-sync every 5 min"
sudo tee /etc/systemd/system/vex1-sync.service >/dev/null <<UNIT
[Unit]
Description=Pull latest Vex1 from GitHub
After=network-online.target
[Service]
Type=oneshot
User=$USER
ExecStart=/usr/bin/git -C $DIR pull -q --ff-only
Nice=10
UNIT
sudo tee /etc/systemd/system/vex1-sync.timer >/dev/null <<UNIT
[Unit]
Description=Sync Vex1 every 5 minutes
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable --now vex1-sync.timer >/dev/null 2>&1
echo "== done"
echo "vault files: $(find "$DIR" -type f -not -path '*/.git/*' | wc -l) | size: $(du -sh --exclude=.git "$DIR" | cut -f1) | last commit: $(git -C "$DIR" log -1 --format='%cr')"
systemctl list-timers vex1-sync.timer --no-pager | sed -n 2p | awk '{print "next sync in:", $3, $4}'

#!/bin/bash
# Installs Tailscale and joins this server to Neel's tailnet. Safe to re-run.
set -euo pipefail
NAME="${TS_HOSTNAME:-vex-micro}"
echo "== 1/2 install Tailscale"
if ! command -v tailscale >/dev/null; then
  curl -fsSL https://tailscale.com/install.sh | sh >/dev/null
fi
if tailscale status >/dev/null 2>&1; then
  echo "== 2/2 already on your tailnet - setting name to $NAME"
  sudo tailscale set --hostname="$NAME"
else
  : "${TS_AUTHKEY:?TS_AUTHKEY missing}"
  echo "== 2/2 join your tailnet as $NAME"
  sudo tailscale up --authkey="$TS_AUTHKEY" --hostname="$NAME"
fi
sleep 3
echo "== done"
tailscale status --self --peers=false | awk '{print "tailnet name:", $2}'

#!/bin/bash
# Installs Tailscale and joins this server to Neel's tailnet. Needs TS_AUTHKEY.
set -euo pipefail
: "${TS_AUTHKEY:?TS_AUTHKEY missing}"
echo "== 1/2 install Tailscale"
if ! command -v tailscale >/dev/null; then
  curl -fsSL https://tailscale.com/install.sh | sh >/dev/null
fi
echo "== 2/2 join your tailnet as $(hostname)"
sudo tailscale up --authkey="$TS_AUTHKEY" --hostname="$(hostname)" --reset
echo "== done"
tailscale status --self --peers=false | awk '{print "tailnet name:", $2, "| status:", $NF}'

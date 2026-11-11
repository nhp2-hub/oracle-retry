#!/bin/bash
# NOTE: this runs via "bash -s" over SSH, so everything is wrapped in main() - otherwise
# apt/pip/curl can eat the rest of the script from stdin.
# Installs the read-only Vex1 MCP server (server/vex1_mcp.py) as a systemd service on
# 127.0.0.1:8765. PRIVATE ONLY - it does NOT turn on Tailscale Funnel. Run that by hand:
#   sudo tailscale funnel --bg 8765
# Safe to re-run: keeps the existing secret token in ~/vex1-mcp/env.
set -euo pipefail

main() {
  local DIR="$HOME/vex1-mcp"

  echo "== 1/4 installing tools"
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq </dev/null
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-venv ripgrep poppler-utils curl </dev/null >/dev/null
  mkdir -p "$DIR"
  curl -fsSL https://raw.githubusercontent.com/nhp2-hub/oracle-retry/main/server/vex1_mcp.py -o "$DIR/vex1_mcp.py" </dev/null
  curl -fsSL https://raw.githubusercontent.com/nhp2-hub/oracle-retry/main/server/vex1_status.py -o "$DIR/vex1_status.py" </dev/null
  curl -fsSL https://raw.githubusercontent.com/nhp2-hub/oracle-retry/main/server/vex1_stream.py -o "$DIR/vex1_stream.py" </dev/null

  echo "== 2/4 installing python stuff (slow part)"
  [ -d "$DIR/venv" ] || python3 -m venv "$DIR/venv"
  # vex1_mcp.py uses the v1 API (mcp.server.fastmcp). mcp 2.x renamed it, so pin <2.
  "$DIR/venv/bin/pip" install -q "mcp<2" </dev/null

  echo "== 3/4 secret token + service"
  if [ ! -s "$DIR/env" ]; then
    ( umask 077; echo "MCP_TOKEN=$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')" > "$DIR/env" )
    echo "== made a NEW token (old connector URLs stop working)"
  else
    echo "== kept the existing token"
  fi
  sudo tee /etc/systemd/system/vex1-mcp.service >/dev/null <<EOF
[Unit]
Description=Vex1 read-only MCP server
After=network-online.target
[Service]
User=$USER
WorkingDirectory=$DIR
EnvironmentFile=$DIR/env
Environment=VAULT=$HOME/vex1
ExecStart=$DIR/venv/bin/python vex1_mcp.py
Restart=on-failure
RestartSec=5
MemoryMax=350M
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
[Install]
WantedBy=multi-user.target
EOF
  sudo systemctl daemon-reload
  sudo systemctl enable vex1-mcp >/dev/null 2>&1
  sudo systemctl restart vex1-mcp

  echo "== 4/4 testing"
  local TOKEN R
  TOKEN=$(cut -d= -f2- "$DIR/env")
  for _ in $(seq 1 40); do
    R=$(curl -s -X POST "http://127.0.0.1:8765/$TOKEN/mcp" \
      -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
      -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}' \
      </dev/null || true)
    if grep -q '"vex1"' <<<"$R"; then
      echo "== done: MCP server is running (private only)"
      echo "== Funnel: $(tailscale funnel status 2>/dev/null | grep -q 8765 && echo ON || echo 'off - run: sudo tailscale funnel --bg 8765')"
      return 0
    fi
    sleep 2
  done
  echo "ERROR: MCP server didn't answer. Last logs:"
  sudo journalctl -u vex1-mcp -n 20 --no-pager | sed 's/^/ERROR: /'
  return 1
}

main "$@"

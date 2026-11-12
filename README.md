# oracle-retry

## Panel + Cockpit (vex-micro)

- **Panel** `https://<funnel host>/<token>/panel`: Beszel-look page served by the same `vex1-mcp` process
  (`server/vex1_panel.py` + `server/vex1_panel.html`). Tabs: Overview (live graphs + health checks), Vault
  (read-only browse/search/preview), Server (units, live logs, processes), Controls (4 buttons).
  The buttons work through a polkit rule that only allows: start `vex1-sync`, start the two `vex1-kick@` jobs,
  restart `vex1-mcp`. Install/update: re-run `server/status.sh`. The HUD stays at `/<token>/status`.
- **Cockpit** (full control, Tailscale only) `https://vex-micro.<tailnet>.ts.net:9090`: run `server/cockpit.sh`
  by hand over SSH. Listens on 127.0.0.1, reached through `tailscale serve` (never Funnel).

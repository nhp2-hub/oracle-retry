"""Health checks for Neel's vex-micro server (standard library only).

Used three ways:
  * imported by vex1_mcp.py  -> the /<MCP_TOKEN>/status page and the `status` MCP tool
  * `python3 vex1_status.py --alert`  -> run every 5 min by vex1-status-alert.timer;
    sends a phone notification (ntfy) when something breaks or gets fixed
  * `python3 vex1_status.py --json`   -> used by the outside watchdog (GitHub Actions)

Every check returns  {"name", "level", "detail"}  with level ok | warn | bad | info.
"""
import html
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

HOME = pathlib.Path.home()
VAULT = pathlib.Path(os.environ.get("VAULT", str(HOME / "vex1")))
MCP_DIR = HOME / "vex1-mcp"
PORT = int(os.environ.get("MCP_PORT", "8765"))
TZ = ZoneInfo("America/Edmonton")
GH_REPO = "nhp2-hub/oracle-retry"
GH_TTL = 15 * 60  # GitHub's no-login limit is 60 calls/hour, so cache
STATE_DIR = pathlib.Path(os.environ.get("STATE_DIRECTORY", str(HOME / ".local/state/vex1-status")))

_gh_cache = {"t": 0.0, "data": None}


# ---------- helpers ----------
def _run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip()
    except Exception as e:  # noqa: BLE001
        return 1, str(e)


def _ago(ts):
    s = max(0, int(time.time() - ts))
    if s < 90:
        return f"{s}s ago"
    if s < 5400:
        return f"{s // 60} min ago"
    if s < 172800:
        return f"{s // 3600} h ago"
    return f"{s // 86400} days ago"


def _local(ts):
    return datetime.fromtimestamp(ts, TZ).strftime("%b %d, %I:%M %p").replace(" 0", " ")


def _env_file(path):
    out = {}
    try:
        for line in pathlib.Path(path).read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


def ntfy_topic():
    return os.environ.get("NTFY_TOPIC") or _env_file(MCP_DIR / "ntfy").get("NTFY_TOPIC", "")


def _check(name, level, detail):
    return {"name": name, "level": level, "detail": detail}


def _systemd(unit, *props):
    code, out = _run(["systemctl", "show", unit, "--no-pager", "-p", ",".join(props)])
    d = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            d[k] = v
    return d


def _ts_from_usec(v):
    try:
        n = int(v)
        return n / 1_000_000 if n > 0 else None
    except (TypeError, ValueError):
        return None


# ---------- checks ----------
def check_server():
    up = float(pathlib.Path("/proc/uptime").read_text().split()[0])
    load = os.getloadavg()[0]
    days, rem = divmod(int(up), 86400)
    return _check("Server", "ok", f"up {days}d {rem // 3600}h · load {load:.2f}")


def check_memory():
    mem = {}
    for line in pathlib.Path("/proc/meminfo").read_text().splitlines():
        k, v = line.split(":", 1)
        mem[k] = int(v.split()[0])
    used = 100 - 100 * mem["MemAvailable"] / mem["MemTotal"]
    swap_t = mem.get("SwapTotal", 0)
    swap = 100 * (swap_t - mem.get("SwapFree", 0)) / swap_t if swap_t else 0
    lvl = "bad" if used > 95 else "warn" if used > 85 or swap > 75 else "ok"
    return _check("Memory", lvl, f"RAM {used:.0f}% used · swap {swap:.0f}% used")


def check_disk():
    st = os.statvfs("/")
    total = st.f_blocks * st.f_frsize
    free = st.f_bavail * st.f_frsize
    used = 100 - 100 * free / total
    lvl = "bad" if used > 92 else "warn" if used > 80 else "ok"
    return _check("Disk", lvl, f"{used:.0f}% used · {free / 1e9:.1f} GB free of {total / 1e9:.0f} GB")


def check_vault_sync():
    timer = _run(["systemctl", "is-active", "vex1-sync.timer"])[1]
    if timer != "active":
        return _check("Vault sync", "bad", f"auto-sync timer is {timer or 'missing'}")
    s = _systemd("vex1-sync.service", "Result", "ExecMainExitTimestampMonotonic", "ExecMainExitTimestamp")
    last = None
    if s.get("ExecMainExitTimestamp"):
        code, out = _run(["date", "-d", s["ExecMainExitTimestamp"], "+%s"])
        if code == 0 and out.isdigit():
            last = int(out)
    if s.get("Result", "success") != "success":
        return _check("Vault sync", "bad", f"last pull failed ({s.get('Result')}) · run `journalctl -u vex1-sync`")
    if last is None:
        return _check("Vault sync", "warn", "no pull recorded yet")
    age = time.time() - last
    lvl = "bad" if age > 3600 else "warn" if age > 1200 else "ok"
    return _check("Vault sync", lvl, f"last pull {_ago(last)} (every 5 min)")


def _git_last(*args):
    code, out = _run(["git", "-C", str(VAULT), "log", "-1", "--format=%ct|%an|%s", *args])
    if code != 0 or "|" not in out:
        return None
    ts, an, subj = out.split("|", 2)
    return int(ts), an, subj


def check_vault_content():
    newest = _git_last()
    if not newest:
        return _check("Vault copy", "bad", "can't read ~/vex1")
    ts, an, subj = newest
    return _check("Vault copy", "info", f"newest change {_ago(ts)} by {an}: {subj[:70]}")


def check_canvas():
    last = _git_last("--author=canvas-sync")
    if not last:
        return _check("Canvas sync", "warn", "no Canvas sync seen in the server's copy yet")
    ts, _, subj = last
    age = time.time() - ts
    lvl = "bad" if age > 60 * 3600 else "warn" if age > 32 * 3600 else "ok"
    return _check("Canvas sync", lvl, f"last run {_ago(ts)} · {subj.replace('Canvas sync: ', '')}")


def check_pc():
    last = _git_last("--grep=^vault backup", "--grep=^Merge", "--author=nhp2-hub")
    if not last:
        return _check("PC pushes", "info", "no PC push in the server's copy yet")
    ts = last[0]
    return _check("PC pushes", "info", f"last PC push {_ago(ts)} ({_local(ts)})")


def check_connector():
    token = os.environ.get("MCP_TOKEN") or _env_file(MCP_DIR / "env").get("MCP_TOKEN", "")
    active = _run(["systemctl", "is-active", "vex1-mcp"])[1]
    if active != "active":
        return _check("Connector", "bad", f"vex1-mcp service is {active or 'missing'}")
    if not token:
        return _check("Connector", "warn", "running, but can't read its token to test it")
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "status", "version": "1"}}}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}/{token}/mcp", data=body, headers={
        "Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            ok = b'"vex1"' in r.read()
    except Exception as e:  # noqa: BLE001
        return _check("Connector", "bad", f"not answering ({type(e).__name__})")
    return _check("Connector", "ok" if ok else "bad", "answering" if ok else "answered with something weird")


def check_tailscale():
    code, out = _run(["tailscale", "status", "--json"])
    try:
        st = json.loads(out)
    except ValueError:
        return _check("Tailscale", "bad", "tailscale isn't answering")
    state = st.get("BackendState")
    if state != "Running":
        return _check("Tailscale", "bad", f"state: {state}")
    code, fs = _run(["tailscale", "funnel", "status"])
    if code != 0:
        return _check("Tailscale", "ok", "connected · Funnel: can't check from here")
    funnel = "8765" in fs and "funnel on" in fs.lower()
    return _check("Tailscale", "ok" if funnel else "bad",
                  "connected · Funnel ON" if funnel else "connected · Funnel is OFF (run: sudo tailscale funnel --bg 8765)")


def _gh(path):
    req = urllib.request.Request(f"https://api.github.com/repos/{GH_REPO}/{path}",
                                 headers={"Accept": "application/vnd.github+json", "User-Agent": "vex1-status"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def check_a1():
    now = time.time()
    if _gh_cache["data"] is None or now - _gh_cache["t"] > GH_TTL:
        try:
            wf = _gh("actions/workflows/oracle-a1-retry.yml")
            runs = _gh("actions/workflows/oracle-a1-retry.yml/runs?per_page=1")["workflow_runs"]
            issues = _gh("issues?state=open&per_page=30")
            _gh_cache.update(t=now, data=(wf, runs, issues))
        except Exception as e:  # noqa: BLE001
            if _gh_cache["data"] is None:
                return _check("A1 retry loop", "info", f"can't reach GitHub right now ({type(e).__name__})")
    wf, runs, issues = _gh_cache["data"]
    titles = [i["title"] for i in issues if "pull_request" not in i]
    if any("instance-vex is up" in t for t in titles):
        return _check("A1 retry loop", "ok", "🎉 THE A1 SERVER IS UP: check the GitHub issue")
    if any("retry loop stopped" in t.lower() for t in titles):
        return _check("A1 retry loop", "warn", "paused after repeated failures (see GitHub issue)")
    if wf.get("state") != "active":
        return _check("A1 retry loop", "warn", f"workflow is {wf.get('state')}")
    if not runs:
        return _check("A1 retry loop", "warn", "no runs yet")
    r = runs[0]
    ts = datetime.fromisoformat(r["created_at"].replace("Z", "+00:00")).timestamp()
    lvl = "warn" if now - ts > 3 * 3600 else "ok"
    return _check("A1 retry loop", lvl, f"still trying (Toronto is full) · last try {_ago(ts)}")


CHECKS = [check_server, check_memory, check_disk, check_vault_sync, check_connector,
          check_tailscale, check_canvas, check_a1, check_pc, check_vault_content]


def collect():
    out = []
    for fn in CHECKS:
        try:
            out.append(fn())
        except Exception as e:  # noqa: BLE001
            out.append(_check(fn.__name__.replace("check_", "").title(), "warn", f"check crashed: {e}"))
    worst = "bad" if any(c["level"] == "bad" for c in out) else "warn" if any(c["level"] == "warn" for c in out) else "ok"
    return {"overall": worst, "checked_at": time.time(), "checks": out}


# ---------- page ----------
ICON = {"ok": "✅", "warn": "⚠️", "bad": "❌", "info": "ℹ️"}
HEADLINE = {"ok": "All good 😎", "warn": "Mostly good, a few things to look at 👀", "bad": "Something's broken 🚨"}


def render_html(st):
    rows = "\n".join(
        f'<div class="row {c["level"]}"><span class="i">{ICON[c["level"]]}</span>'
        f'<div><b>{html.escape(c["name"])}</b><br><span>{html.escape(c["detail"])}</span></div></div>'
        for c in st["checks"])
    topic = ntfy_topic()
    alerts = (f'Alerts go to ntfy topic <code>{html.escape(topic)}</code>' if topic
              else "Phone alerts aren't set up yet")
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="30">
<meta name="robots" content="noindex"><title>Vex1 status</title>
<style>
:root{{color-scheme:light dark;--bg:#f5f5f4;--card:#fff;--muted:#6b7280}}
@media(prefers-color-scheme:dark){{:root{{--bg:#111;--card:#1c1c1e;--muted:#9ca3af}}}}
body{{font:16px/1.4 -apple-system,system-ui,sans-serif;background:var(--bg);margin:0;padding:20px;max-width:640px;margin:auto}}
h1{{font-size:22px;margin:4px 0}} .sub{{color:var(--muted);font-size:13px;margin-bottom:16px}}
.big{{padding:14px 16px;border-radius:14px;font-weight:600;margin-bottom:14px;background:var(--card)}}
.big.ok{{border-left:6px solid #22c55e}} .big.warn{{border-left:6px solid #f59e0b}} .big.bad{{border-left:6px solid #ef4444}}
.row{{display:flex;gap:12px;background:var(--card);padding:12px 14px;border-radius:12px;margin:8px 0}}
.row span{{color:var(--muted);font-size:14px}} .row .i{{font-size:20px;color:inherit}}
.row.bad{{outline:2px solid #ef4444}} .row.warn{{outline:1px solid #f59e0b}}
code{{font-size:12px}} footer{{color:var(--muted);font-size:12px;margin-top:16px}}
</style></head><body>
<h1>🖥️ Vex1 status</h1>
<div class="sub">Checked {_local(st["checked_at"])} (Edmonton time) · refreshes every 30 s</div>
<div class="big {st["overall"]}">{HEADLINE[st["overall"]]}</div>
{rows}
<footer>{alerts} · the outside watchdog also checks every ~30 min.</footer>
</body></html>"""


def render_text(st):
    lines = [f"{HEADLINE[st['overall']]} (checked {_local(st['checked_at'])})"]
    lines += [f"{ICON[c['level']]} {c['name']}: {c['detail']}" for c in st["checks"]]
    return "\n".join(lines)


# ---------- alerts ----------
def notify(title, message, priority=3, tags=()):
    """Send a phone notification through ntfy.sh (priority 3 = normal, 4 = high)."""
    topic = ntfy_topic()
    if not topic:
        print("no NTFY_TOPIC set, skipping notification:", title)
        return False
    body = json.dumps({"topic": topic, "title": title, "message": message,
                       "priority": priority, "tags": list(tags)}).encode()
    req = urllib.request.Request("https://ntfy.sh/", data=body, headers={"Content-Type": "application/json"})
    for _ in range(3):
        try:
            urllib.request.urlopen(req, timeout=15).read()
            return True
        except Exception as e:  # noqa: BLE001
            print("ntfy failed:", e)
            time.sleep(5)
    return False


def run_alerts():
    """Ping the phone when a check turns red, and again when it's fixed.
    A check has to be red twice in a row (10 min) before it alerts, so blips don't spam."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    f = STATE_DIR / "state.json"
    try:
        prev = json.loads(f.read_text())
    except (OSError, ValueError):
        prev = {}
    st = collect()
    new = {}
    for c in st["checks"]:
        p = prev.get(c["name"], {"level": "ok", "bad_runs": 0, "alerted": False})
        bad_runs = p["bad_runs"] + 1 if c["level"] == "bad" else 0
        alerted = p["alerted"]
        if bad_runs >= 2 and not alerted:
            alerted = notify(f"Vex1: {c['name']} is broken", c["detail"], 4, ["rotating_light"])
        elif bad_runs == 0 and alerted:
            alerted = not notify(f"Vex1: {c['name']} is fixed", c["detail"], 3, ["white_check_mark"])
        if c["name"] == "A1 retry loop" and "IS UP" in c["detail"] and not p.get("a1_told"):
            p["a1_told"] = notify("Vex1: the A1 server landed!", "Oracle finally had room. Check the GitHub issue.", 4, ["tada"])
        new[c["name"]] = {"level": c["level"], "bad_runs": bad_runs, "alerted": alerted,
                          "a1_told": p.get("a1_told", False)}
    f.write_text(json.dumps(new))
    print(render_text(st))


if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    if arg == "--alert":
        run_alerts()
    elif arg == "--json":
        print(json.dumps(collect()))
    elif arg == "--test-alert":
        sys.exit(0 if notify("Vex1: test alert 👋", "If you see this, phone alerts work.", 3, ["wave"]) else 1)
    else:
        print(render_text(collect()))

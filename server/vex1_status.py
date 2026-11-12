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


# ---------- page (live HUD + stream) ----------
ICON = {"ok": "✅", "warn": "⚠️", "bad": "❌", "info": "ℹ️"}
HEADLINE = {"ok": "All good 😎", "warn": "Mostly good, a few things to look at 👀", "bad": "Something's broken 🚨"}


def render_html(st):
    """Live HUD. First reading is inlined; the page then streams CPU/RAM/network from
    /<token>/stream (~100x/s) and re-polls the full checks every 15 s. Drawn at 60 fps."""
    boot = json.dumps({"st": st, "topic": ntfy_topic()}).replace("</", "<\\/")
    return HUD_PAGE.replace("__BOOT__", boot)


HUD_PAGE = r"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex">
<meta name="apple-mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="theme-color" content="#05080c"><title>Vex1 HUD</title>
<noscript><meta http-equiv="refresh" content="30"></noscript>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@400;600&display=swap" rel="stylesheet">
<style>
:root{--bg:#05080c;--line:rgba(124,196,255,.22);--txt:#bfe6ff;--dim:#6d9cbd;--sys:#3ddc97;color-scheme:dark}
*{box-sizing:border-box}
html,body{margin:0;min-height:100%;background:radial-gradient(1200px 700px at 50% -10%,#0d2233 0%,var(--bg) 60%) fixed;color:var(--txt);
 font:15px/1.4 "Chakra Petch",ui-monospace,monospace}
body:before{content:"";position:fixed;inset:0;background:repeating-linear-gradient(0deg,rgba(124,196,255,.04) 0 1px,transparent 1px 4px);pointer-events:none}
.wrap{max-width:1000px;margin:0 auto;padding:max(20px,env(safe-area-inset-top)) 18px max(28px,env(safe-area-inset-bottom))}
.top{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;letter-spacing:.18em;font-size:12px;color:#6fb9e8;text-transform:uppercase}
.live{display:inline-flex;align-items:center;gap:8px;font-variant-numeric:tabular-nums}
.live i{width:7px;height:7px;border-radius:50%;background:#3ddc97;box-shadow:0 0 8px #3ddc97;animation:pulse 1s ease-in-out infinite}
.live.stale i{background:#ff5d6c;box-shadow:0 0 8px #ff5d6c}
.status{margin:18px 0 0;padding:10px 14px;border:1px solid var(--line);letter-spacing:.2em;font-size:13px;color:var(--sys);transition:color .6s;
 clip-path:polygon(0 0,calc(100% - 12px) 0,100% 12px,100% 100%,12px 100%,0 calc(100% - 12px));background:rgba(10,30,45,.45)}
.status:before{content:"";display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--sys);box-shadow:0 0 10px var(--sys);margin-right:10px;animation:pulse 2s ease-in-out infinite}
@keyframes pulse{50%{opacity:.35}}
.core{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin:22px 0 14px}
.ring{display:flex;flex-direction:column;align-items:center;gap:6px}
.ring svg{width:140px;height:140px}
.ring b{font-size:13px;letter-spacing:.2em;text-transform:uppercase;color:#8fd3ff}
.ring span{font-size:12px;color:#5d8fb3;font-variant-numeric:tabular-nums}
.spin{transform-origin:75px 75px;animation:spin 14s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.graphs{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:10px;margin-bottom:14px}
.gp{border:1px solid var(--line);background:rgba(10,30,45,.45);padding:10px 12px 8px;
 clip-path:polygon(0 0,calc(100% - 12px) 0,100% 12px,100% 100%,12px 100%,0 calc(100% - 12px))}
.gp .h{display:flex;justify-content:space-between;font-size:11px;letter-spacing:.18em;color:#6fb9e8;text-transform:uppercase;font-variant-numeric:tabular-nums}
.gp .h b{color:#e6f6ff;font-weight:600;letter-spacing:.06em}
.gp canvas{width:100%;height:90px;display:block;margin-top:6px}
.list{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:8px}
.it{border:1px solid var(--line);padding:10px 12px;display:flex;justify-content:space-between;gap:12px;background:rgba(10,30,45,.45);
 clip-path:polygon(0 0,calc(100% - 10px) 0,100% 10px,100% 100%,10px 100%,0 calc(100% - 10px));transition:border-color .6s,background .6s}
.it.bad{border-color:#ff5d6c;background:rgba(60,10,18,.5)} .it.warn{border-color:rgba(255,181,71,.6)}
.it em{font-style:normal;font-size:12px;color:var(--dim);text-align:right;max-width:60%}
.tag{font-size:11px;letter-spacing:.15em}
footer{margin-top:18px;font-size:11px;letter-spacing:.12em;color:#4f7896;display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap}
code{font:11px ui-monospace,monospace;color:#6fb9e8}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style></head><body><div class="wrap">
<div class="top"><span>VEX-MICRO // SYSTEM</span><span class="live" id="live"><i></i><span id="rate">CONNECTING</span></span></div>
<div class="status" id="status"></div>
<div class="core" id="core"></div>
<div class="graphs">
  <div class="gp"><div class="h"><span>CPU · 15 s</span><b id="cpuv">0%</b></div><canvas id="gcpu"></canvas></div>
  <div class="gp"><div class="h"><span>NETWORK · 15 s</span><b id="netv">0 KB/s</b></div><canvas id="gnet"></canvas></div>
</div>
<div class="list" id="list"></div>
<footer><span id="alerts"></span><span><a href="panel" style="color:inherit">PANEL ↗</a> · STREAM ~100/S · CHECKS EVERY 15 S · WATCHDOG ~30 MIN</span></footer>
</div>
<script>
const BOOT = __BOOT__;
const COL = {ok:"#3ddc97",warn:"#ffb547",bad:"#ff5d6c",info:"#8fd3ff"};
const WORD = {ok:"OK",warn:"WATCH",bad:"DOWN",info:"INFO"};
const HEAD = {ok:"ALL SYSTEMS NOMINAL",warn:"SYSTEMS ONLINE · CHECK FLAGGED ITEMS",bad:"ALERT · SYSTEM FAILURE"};
const ORDER = {bad:0,warn:1,ok:2,info:3};
const R = 58, CIRC = 2*Math.PI*R, SPAN = 15000;
const esc = s => String(s).replace(/[&<>"]/g, m => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[m]));
const pct = (txt, word) => { const m = new RegExp(word + "\\D{0,12}?(\\d+)%").exec(txt||""); return m ? +m[1] : 0; };
const kb = b => b >= 1048576 ? (b/1048576).toFixed(1)+" MB/s" : (b/1024).toFixed(b<10240?1:0)+" KB/s";

// ---- rings ----
const rings = {};
function ringSVG(id, label){
  return `<div class="ring"><svg viewBox="0 0 150 150" role="img" aria-label="${label}">
  <circle cx="75" cy="75" r="70" fill="none" stroke="rgba(124,196,255,.15)" stroke-width="1"/>
  <g class="spin"><circle id="${id}-dash" cx="75" cy="75" r="70" fill="none" stroke-width="1.5" stroke-dasharray="4 14" opacity=".6"/></g>
  <circle cx="75" cy="75" r="${R}" fill="none" stroke="rgba(124,196,255,.12)" stroke-width="8"/>
  <circle id="${id}-arc" cx="75" cy="75" r="${R}" fill="none" stroke-width="8" stroke-linecap="round"
    stroke-dasharray="${CIRC}" stroke-dashoffset="${CIRC}" transform="rotate(-90 75 75)"/>
  <text id="${id}-num" x="75" y="83" text-anchor="middle" fill="#e6f6ff" font-size="26" font-family="Chakra Petch,monospace">0%</text></svg>
  <b>${label}</b><span id="${id}-sub">&nbsp;</span></div>`;
}
document.getElementById("core").innerHTML = ringSVG("sys","Systems")+ringSVG("cpu","CPU")+ringSVG("mem","Memory")+ringSVG("dsk","Disk");
for (const id of ["sys","cpu","mem","dsk"]) rings[id] = {shown:0, target:0, color:null,
  arc:document.getElementById(id+"-arc"), num:document.getElementById(id+"-num"), dash:document.getElementById(id+"-dash"), sub:document.getElementById(id+"-sub")};
function setRing(id, v, color, sub){ const r=rings[id]; r.target=Math.max(0,Math.min(100,v)); if(color&&color!==r.color){r.color=color; r.arc.style.stroke=color; r.arc.style.filter=`drop-shadow(0 0 6px ${color})`; r.dash.style.stroke=color;} if(sub!==undefined) r.sub.textContent=sub; }
for (const id in rings) setRing(id, 0, "#7cc4ff");

// ---- slow checks (every 15 s) ----
function drawChecks(st){
  const by = Object.fromEntries(st.checks.map(c => [c.name, c]));
  const nOk = st.checks.filter(c => c.level==="ok"||c.level==="info").length;
  const sys = st.overall==="ok" ? COL.ok : COL[st.overall];
  document.documentElement.style.setProperty("--sys", sys);
  document.getElementById("status").textContent = HEAD[st.overall];
  const mem = by["Memory"]||{detail:"",level:"ok"}, dsk = by["Disk"]||{detail:"",level:"ok"};
  const hot = (c, base) => (c.level==="warn"||c.level==="bad") ? COL[c.level] : base;
  setRing("sys", 100*nOk/Math.max(1,st.checks.length), sys, `${nOk}/${st.checks.length} nominal`);
  setRing("dsk", pct(dsk.detail,""), hot(dsk,"#a78bfa"), (dsk.detail.split("·")[1]||"").trim());
  if (!live.on) { setRing("mem", pct(mem.detail,"RAM"), hot(mem,"#7cc4ff"), `swap ${pct(mem.detail,"swap")}%`); }
  rings.mem.hot = hot(mem,"#7cc4ff");
  document.getElementById("list").innerHTML = st.checks.slice().sort((a,b)=>ORDER[a.level]-ORDER[b.level]).map(c =>
    `<div class="it ${c.level}"><div><div class="tag" style="color:${COL[c.level]}">● ${WORD[c.level]}</div>${esc(c.name)}</div><em>${esc(c.detail)}</em></div>`).join("");
}
async function pollChecks(){
  try{ const r = await fetch(location.pathname+"?format=json",{cache:"no-store"}); if(r.ok) drawChecks(await r.json()); }catch(e){}
  setTimeout(pollChecks, document.hidden ? 60000 : 15000);
}

// ---- fast stream (~100/s) ----
const live = {on:false, es:null, last:0, count:0, rate:0, cpu:[], net:[], peakNet:1024};
function openStream(){
  if (live.es) return;
  live.es = new EventSource(location.pathname.replace(/\/status\/?$/, "/stream"));
  live.es.onmessage = e => {
    let d; try{ d = JSON.parse(e.data); }catch(_){ return; }
    if (d.cpu === undefined) return;
    const now = performance.now(); live.on = true; live.last = now; live.count++;
    live.cpu.push([now, d.cpu]); live.net.push([now, d.rx + d.tx]);
    const cpuCol = d.cpu > 90 ? COL.bad : d.cpu > 70 ? COL.warn : "#5eead4";
    setRing("cpu", d.cpu, cpuCol, `load ${d.load}`);
    setRing("mem", d.ram, d.ram > 95 ? COL.bad : d.ram > 85 ? COL.warn : (rings.mem.hot||"#7cc4ff"), `swap ${d.swap.toFixed(0)}%`);
    live.netNow = d.rx + d.tx; live.cpuNow = d.cpu; live.rx = d.rx; live.tx = d.tx;
  };
}
function closeStream(){ if (live.es){ live.es.close(); live.es = null; } }
setInterval(() => { live.rate = live.count; live.count = 0; }, 1000);

// ---- 60 fps draw loop ----
function sizeCanvas(c){ const dpr = devicePixelRatio||1, w = c.clientWidth, h = c.clientHeight;
  if (c.width !== Math.round(w*dpr)) { c.width = Math.round(w*dpr); c.height = Math.round(h*dpr); } return [c.getContext("2d"), w, h, dpr]; }
function graph(c, pts, max, color, now){
  const [g, w, h, dpr] = sizeCanvas(c); g.setTransform(dpr,0,0,dpr,0,0); g.clearRect(0,0,w,h);
  g.strokeStyle = "rgba(124,196,255,.12)"; g.lineWidth = 1;
  for (const f of [.25,.5,.75]) { g.beginPath(); g.moveTo(0,h*f); g.lineTo(w,h*f); g.stroke(); }
  if (pts.length < 2) return;
  const x = t => w - (now - t)/SPAN*w, y = v => h - 3 - (v/max)*(h-8);
  g.beginPath(); pts.forEach(([t,v],i) => i ? g.lineTo(x(t),y(v)) : g.moveTo(x(t),y(v)));
  const lx = x(pts[pts.length-1][0]), ly = y(pts[pts.length-1][1]);
  g.strokeStyle = color; g.lineWidth = 1.6; g.shadowColor = color; g.shadowBlur = 8; g.stroke(); g.shadowBlur = 0;
  g.lineTo(lx,h); g.lineTo(x(pts[0][0]),h); g.closePath();
  const grad = g.createLinearGradient(0,0,0,h); grad.addColorStop(0,color+"55"); grad.addColorStop(1,color+"00"); g.fillStyle = grad; g.fill();
  g.beginPath(); g.arc(lx,ly,3,0,7); g.fillStyle = color; g.fill();
}
const gcpu = document.getElementById("gcpu"), gnet = document.getElementById("gnet");
function frame(){
  const now = performance.now();
  for (const id in rings){ const r = rings[id]; r.shown += (r.target - r.shown) * 0.18;
    if (Math.abs(r.target-r.shown) < .05) r.shown = r.target;
    r.arc.style.strokeDashoffset = CIRC*(1 - r.shown/100); r.num.textContent = Math.round(r.shown)+"%"; }
  while (live.cpu.length && now - live.cpu[0][0] > SPAN+500) live.cpu.shift();
  while (live.net.length && now - live.net[0][0] > SPAN+500) live.net.shift();
  live.peakNet = Math.max(1024, ...live.net.map(p=>p[1]).slice(-1500)) * 1.2;
  graph(gcpu, live.cpu, 100, "#5eead4", now);
  graph(gnet, live.net, live.peakNet, "#a78bfa", now);
  if (live.on){ document.getElementById("cpuv").textContent = (live.cpuNow||0).toFixed(1)+"%";
    document.getElementById("netv").textContent = "↓ "+kb(live.rx||0)+"  ↑ "+kb(live.tx||0); }
  const age = (now - live.last)/1000, lv = document.getElementById("live");
  lv.classList.toggle("stale", !live.on || age > 3);
  document.getElementById("rate").textContent = !live.on ? "CONNECTING" : age > 3 ? `NO SIGNAL · ${Math.round(age)}s` : `LIVE · ${live.rate}/s`;
  requestAnimationFrame(frame);
}

document.addEventListener("visibilitychange", () => { if (document.hidden) closeStream(); else { openStream(); pollChecks(); } });
document.getElementById("alerts").innerHTML = BOOT.topic ? `ALERTS → NTFY <code>${esc(BOOT.topic)}</code>` : "PHONE ALERTS NOT SET UP";
drawChecks(BOOT.st);
openStream();
setTimeout(pollChecks, 15000);
requestAnimationFrame(frame);
</script></body></html>"""


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

"""The Vex1 control panel (Beszel look) at  /<MCP_TOKEN>/panel.

Runs inside the vex1-mcp process (see vex1_mcp.py), so there's nothing extra to keep alive.
The page itself is vex1_panel.html; this file is the small JSON API behind it:

  panel/api/sys            server facts for the systems table
  panel/api/ls|search|note|pdf|pdfpage|raw|feed     read-only vault browser
  panel/api/server         vex1 services + timers, top processes
  panel/api/logs           live journalctl for the vex1 units (Server-Sent Events)
  panel/api/run            the 4 buttons (POST starts one, GET shows how it's going)

What the buttons can do is fixed in ACTIONS below. They only work because of the polkit
rule that status.sh installs, which lets this user start exactly those units and nothing
else. The service still can't write files, sudo, or run commands.
"""
import asyncio
import json
import mimetypes
import os
import pathlib
import subprocess
import time
import urllib.request

from starlette.requests import Request
from starlette.responses import FileResponse, HTMLResponse, JSONResponse, Response, StreamingResponse

import vex1_status

HERE = pathlib.Path(__file__).resolve().parent
STARTED = time.time()
HEADERS = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Robots-Tag": "noindex",
           "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff"}

# ---- the only things the Controls tab can do: name -> (unit, systemctl verb) ----
ACTIONS = {
    "sync": ("vex1-sync.service", "start"),
    "a1": ("vex1-kick@oracle-a1-retry.service", "start"),
    "watchdog": ("vex1-kick@watchdog.service", "start"),
    "restart": ("vex1-mcp.service", "restart"),
}
COOLDOWN = 10  # seconds between presses of the same button

UNITS = [  # (unit, what it does, the service a timer starts)
    ("vex1-mcp.service", "Connector + status page + this panel", None),
    ("vex1-sync.timer", "git pull of the vault, every 5 min", "vex1-sync.service"),
    ("vex1-status-alert.timer", "Health checks → ntfy alerts, every 5 min", "vex1-status-alert.service"),
    ("vex1-kick@oracle-a1-retry.timer", "Backup: starts the A1 retry on GitHub", "vex1-kick@oracle-a1-retry.service"),
    ("vex1-kick@watchdog.timer", "Backup: starts the Watchdog on GitHub", "vex1-kick@watchdog.service"),
    ("tailscaled.service", "Tailscale + Funnel", None),
    ("cockpit.socket", "Cockpit admin panel (Tailscale only)", None),
]
LOG_UNITS = {  # ?unit= value -> journalctl -u patterns
    "all": ["vex1-*"],
    "vex1-mcp": ["vex1-mcp.service"],
    "vex1-sync": ["vex1-sync.service"],
    "vex1-status-alert": ["vex1-status-alert.service"],
    "vex1-kick": ["vex1-kick@*"],
}
TEXT_EXT = {".md", ".txt", ".csv", ".tsv", ".json", ".canvas", ".py", ".m", ".tex", ".yml", ".yaml", ".html",
            ".htm", ".js", ".css", ".xml", ".ini", ".cfg", ".log", ".sh", ".ps1", ".bat", ".c", ".cpp", ".h", ".ipynb"}
IMG_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}
NOTE_MAX = 200_000        # characters of a note sent to the page
RAW_MAX = 12 * 1024 * 1024  # biggest image we'll send
LS_MAX = 1500

_state = {"oci": None, "oci_t": 0.0, "feed": (None, None), "procs": (0.0, {}), "runs": {}, "logs": 0,
          "restart_error": "", "html": (0.0, "")}
_pdf_lock = asyncio.Semaphore(1)     # one PDF page render at a time (1/8 OCPU)
_search_lock = asyncio.Semaphore(2)


def _json(data, status=200):
    return JSONResponse(data, status_code=status, headers=HEADERS)


def _run(cmd, timeout=15):
    """-> (exit code, stdout, stderr); never raises."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        return r.returncode, r.stdout, r.stderr.strip()
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)


def _secrets():
    out = [s for s in (os.environ.get("MCP_TOKEN", ""), vex1_status.ntfy_topic()) if s]
    return out


def _redact(text):
    for s in _secrets():
        text = text.replace(s, "•••")
    return text


def _unix(v):
    """'@1794450001' (systemctl --timestamp=unix) -> 1794450001, anything else -> None."""
    v = (v or "").strip()
    if v.startswith("@"):
        try:
            n = float(v[1:])
            return n if n > 0 else None
        except ValueError:
            return None
    return None


def _show(units, props):
    """systemctl show for several units at once -> {unit: {prop: value}}."""
    code, out, _ = _run(["systemctl", "show", *units, "--no-pager", "--timestamp=unix", "-p", ",".join(["Id", *props])])
    res = {}
    for block in out.split("\n\n"):
        d = {}
        for line in block.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                d[k] = v
        if d.get("Id"):
            res[d["Id"]] = d
    return res


# ---------------------------------------------------------------- sys
def _oci():
    """Shape / region / fault domain from Oracle's metadata service (cached)."""
    now = time.time()
    if _state["oci"] is None and now - _state["oci_t"] > 600:
        _state["oci_t"] = now
        try:
            req = urllib.request.Request("http://169.254.169.254/opc/v2/instance/",
                                         headers={"Authorization": "Bearer Oracle"})
            with urllib.request.urlopen(req, timeout=2) as r:
                d = json.loads(r.read())
            _state["oci"] = {"shape": d.get("shape", ""), "region": d.get("canonicalRegionName", ""),
                             "fd": (d.get("faultDomain", "") or "").replace("FAULT-DOMAIN-", "FD-")}
        except Exception:  # noqa: BLE001
            pass
    return _state["oci"] or {}


def _sys():
    osname = ""
    try:
        for line in pathlib.Path("/etc/os-release").read_text().splitlines():
            if line.startswith("PRETTY_NAME="):
                osname = line.split("=", 1)[1].strip('"')
    except OSError:
        pass
    st = os.statvfs("/")
    total, free = st.f_blocks * st.f_frsize, st.f_bavail * st.f_frsize
    cockpit = ""
    if _run(["systemctl", "is-active", "cockpit.socket"])[1].strip() == "active":
        try:
            name = json.loads(_run(["tailscale", "status", "--json"])[1])["Self"]["DNSName"].rstrip(".")
            cockpit = f"https://{name}:9090"
        except Exception:  # noqa: BLE001
            cockpit = ""
    return {"host": os.uname().nodename, "os": osname, "uptime": float(pathlib.Path("/proc/uptime").read_text().split()[0]),
            "disk_pct": round(100 - 100 * free / total, 1), "disk_free_gb": round(free / 1e9, 1),
            "disk_total_gb": round(total / 1e9), "cpus": os.cpu_count(), "started": STARTED,
            "restart_error": _state["restart_error"], "cockpit": cockpit, **_oci()}


# ---------------------------------------------------------------- vault
def _hidden(name):
    return name.startswith(".")


def _ls(root, vault):
    out = []
    try:
        kids = sorted(os.scandir(root), key=lambda e: (not e.is_dir(), e.name.lower()))
    except OSError:
        return {"entries": [], "error": "can't open that folder"}
    for e in kids:
        if _hidden(e.name):
            continue
        try:
            st = e.stat()
        except OSError:
            continue
        out.append({"n": e.name, "d": e.is_dir(), "s": 0 if e.is_dir() else st.st_size, "m": int(st.st_mtime)})
        if len(out) >= LS_MAX:
            break
    return {"path": "" if root == vault else str(root.relative_to(vault)), "entries": out, "more": len(out) >= LS_MAX}


def _search(q, vault, limit=60):
    ql = q.lower()
    names = []
    for dirpath, dirs, files in os.walk(vault):
        dirs[:] = [d for d in dirs if not _hidden(d)]
        rel = os.path.relpath(dirpath, vault)
        for f in files:
            if ql in f.lower() and not _hidden(f):
                p = pathlib.Path(dirpath, f)
                try:
                    st = p.stat()
                except OSError:
                    continue
                names.append({"p": f if rel == "." else f"{rel}/{f}", "s": st.st_size, "m": int(st.st_mtime)})
                if len(names) >= limit:
                    break
        if len(names) >= limit:
            break
    code, out, _ = _run(["rg", "-i", "-F", "-n", "--no-heading", "--max-count", "2", "--max-columns", "200",
                         "--max-columns-preview", "-g", "!.git", "-g", "!*.pdf", "--", q, str(vault)], timeout=25)
    text = []
    pre = str(vault) + "/"
    for line in out.splitlines():
        if line.startswith(pre):
            line = line[len(pre):]
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[1].isdigit():
            text.append({"p": parts[0], "l": int(parts[1]), "t": parts[2].strip()[:220]})
        if len(text) >= limit:
            break
    return {"names": names, "text": text}


def _note(p):
    size = p.stat().st_size
    with open(p, "rb") as f:
        raw = f.read(NOTE_MAX * 4)
    if p.suffix.lower() not in TEXT_EXT and b"\0" in raw[:8192]:
        return {"binary": True, "size": size}
    text = raw.decode("utf-8", errors="replace")
    return {"text": text[:NOTE_MAX], "truncated": len(text) > NOTE_MAX or size > len(raw), "size": size}


def _pdf_pages(p):
    code, out, _ = _run(["pdfinfo", str(p)], timeout=20)
    for line in out.splitlines():
        if line.startswith("Pages:"):
            try:
                return int(line.split()[1])
            except (IndexError, ValueError):
                break
    return 0


def _pdf_page(p, page):
    """One page as a JPEG (bytes), small enough to be quick on the Micro."""
    try:
        r = subprocess.run(["nice", "-n", "10", "pdftoppm", "-jpeg", "-r", "80", "-f", str(page), "-l", str(page), str(p)],
                           capture_output=True, timeout=45)
        return r.stdout if r.returncode == 0 and r.stdout[:2] == b"\xff\xd8" else b""
    except Exception:  # noqa: BLE001
        return b""


def _who(author, subject):
    a, s = author.lower(), subject.lower()
    if "canvas" in a or s.startswith("canvas sync"):
        return "Canvas bot"
    if "claude" in a or "claude" in s[:40]:
        return "Claude"
    if s.startswith("vault backup") or s.startswith("merge"):
        return "PC"
    return author[:18] or "?"


def _feed(vault, n=30):
    git = ["git", "-c", "core.quotepath=false", "-C", str(vault)]
    head = _run([*git, "rev-parse", "--short", "HEAD"])[1].strip()
    sync = _show(["vex1-sync.service"], ["ExecMainExitTimestamp"]).get("vex1-sync.service", {})
    last_pull = _unix(sync.get("ExecMainExitTimestamp"))
    if _state["feed"][0] != head or not head:
        code, out, _ = _run([*git, "log", "-n", str(n), "--name-only", "--format=%x1e%ct%x1f%an%x1f%s"], timeout=30)
        commits = []
        for rec in out.split("\x1e")[1:]:
            lines = rec.strip("\n").split("\n")
            try:
                ts, an, subj = lines[0].split("\x1f", 2)
            except ValueError:
                continue
            files = [x for x in lines[1:] if x.strip()]
            where = ""
            if files:
                try:
                    where = os.path.commonpath(files[:400]) if len(files) > 1 else os.path.dirname(files[0])
                except ValueError:
                    where = ""
            commits.append({"t": int(ts), "who": _who(an, subj), "s": subj[:140], "n": len(files),
                            "where": where, "file": files[0] if len(files) == 1 else ""})
        _state["feed"] = (head, commits)
    return {"head": head, "last_pull": last_pull, "commits": _state["feed"][1] or []}


# ---------------------------------------------------------------- server tab
def _timers():
    """{timer unit: (last run, next run)} in unix seconds (None when unknown)."""
    res = {}
    code, out, _ = _run(["systemctl", "list-timers", "--all", "--no-pager", "--output=json"])
    try:
        for t in json.loads(out):
            last, nxt = t.get("last"), t.get("next")
            res[t.get("unit")] = (last / 1e6 if last else None, nxt / 1e6 if nxt else None)
    except (ValueError, TypeError, AttributeError):
        pass
    return res


def _units():
    names = [u for u, _, _ in UNITS] + [s for _, _, s in UNITS if s]
    info = _show(names, ["LoadState", "ActiveState", "SubState", "Result", "ActiveEnterTimestamp",
                         "LastTriggerUSec", "NextElapseUSecRealtime"])
    timers = _timers()
    rows = []
    for unit, what, svc in UNITS:
        d = info.get(unit, {})
        if d.get("LoadState", "not-found") != "loaded":
            if unit == "cockpit.socket":
                continue  # optional extra: only listed once it's installed
            rows.append({"unit": unit, "what": what, "state": "not installed", "lvl": "off", "last": None, "next": None})
            continue
        active = d.get("ActiveState", "?")
        if svc:  # a timer
            last, nxt = timers.get(unit, (None, None))
            last = last or _unix(d.get("LastTriggerUSec"))
            nxt = nxt or _unix(d.get("NextElapseUSecRealtime"))
            failed = info.get(svc, {}).get("Result", "success") not in ("success", "")
            running = info.get(svc, {}).get("ActiveState") in ("activating", "active")
            if active != "active":
                state, lvl = f"timer {active}", "bad"
            elif failed:
                state, lvl = "last run failed", "bad"
            elif running:
                state, lvl = "running now", "ok"
            else:
                state, lvl = "waiting", "wait"
            rows.append({"unit": unit, "what": what, "state": state, "lvl": lvl, "last": last, "next": nxt})
        else:
            since = _unix(d.get("ActiveEnterTimestamp"))
            lvl = "ok" if active == "active" else "bad" if active == "failed" else "off"
            sub = d.get("SubState", "")
            rows.append({"unit": unit, "what": what, "state": active if sub in ("", active) else f"{active} ({sub})",
                         "lvl": lvl, "since": since if active == "active" else None, "last": None, "next": None})
    return rows


def _procs(top=8):
    tick = os.sysconf("SC_CLK_TCK")
    page = os.sysconf("SC_PAGE_SIZE")
    now = time.monotonic()
    prev_t, prev = _state["procs"]
    cur, rows = {}, []
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            stat = pathlib.Path(f"/proc/{pid}/stat").read_text()
            name = stat[stat.index("(") + 1:stat.rindex(")")]
            f = stat[stat.rindex(")") + 2:].split()
            ticks = int(f[11]) + int(f[12])
            rss = int(f[21]) * page
            if rss == 0:
                continue  # kernel thread
            if name.startswith("python"):
                args = pathlib.Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
                script = next((a.decode(errors="replace") for a in args[1:] if a and not a.startswith(b"-")), "")
                if script:
                    name = f"python · {os.path.basename(script)}"
        except (OSError, ValueError, IndexError):
            continue
        cur[pid] = ticks
        cpu = 100 * (ticks - prev[pid]) / tick / (now - prev_t) if pid in prev and now > prev_t else 0.0
        rows.append({"pid": int(pid), "name": name, "cpu": round(max(0.0, cpu), 1), "mb": round(rss / 1048576, 1)})
    _state["procs"] = (now, cur)
    rows.sort(key=lambda r: -r["mb"])
    return rows[:top]


# ---------------------------------------------------------------- controls
def _run_status(name):
    """How the last press of a button is going: running | done | failed (+ its log lines)."""
    run = _state["runs"].get(name)
    if not run:
        return {"state": "idle", "lines": []}
    unit, t0 = run["unit"], run["t0"]
    if run.get("error"):
        return {"state": "failed", "lines": [run["error"]]}
    d = _show([unit], ["ActiveState", "Result", "ExecMainStartTimestamp"]).get(unit, {})
    began = (_unix(d.get("ExecMainStartTimestamp")) or 0) >= int(t0) - 1
    active = d.get("ActiveState", "")
    if active in ("activating", "active", "deactivating", "reloading") or (not began and time.time() - t0 < 8):
        state = "running"
    elif active == "failed" or d.get("Result", "success") not in ("success", ""):
        state = "failed"
    else:
        state = "done"
    code, out, _ = _run(["journalctl", "-u", unit, "--since", f"@{int(t0)}", "-o", "cat", "--no-pager", "-n", "30"])
    lines = [_redact(x)[:300] for x in out.splitlines() if x.strip() and not x.startswith("-- ")]
    if state == "done" and name == "sync":
        code, out, _ = _run(["git", "-C", str(vex1_status.VAULT), "log", "-1", "--format=%h · %s (%cr)"])
        if out.strip():
            lines.append("vault is at " + out.strip()[:160])
    return {"state": state, "lines": lines}


def _explain(err):
    e = err.lower()
    if "not found" in e or "not loaded" in e:
        return "That job isn't installed on the server yet (run the kick.sh setup first)."
    if "denied" in e or "authentication" in e or "not authorized" in e or "polkit" in e:
        return "The panel isn't allowed to do that yet: re-run the status.sh install (it adds the permission)."
    return _redact(err)[:300] or "systemctl failed"


def _start(name):
    unit, verb = ACTIONS[name]
    t0 = time.time()
    _state["runs"][name] = {"unit": unit, "t0": t0}
    code, out, err = _run(["systemctl", verb, "--no-block", "--no-ask-password", unit], timeout=20)
    if code != 0:
        _state["runs"][name]["error"] = _explain(err)
        return {"ok": False, "error": _state["runs"][name]["error"]}
    return {"ok": True}


async def _restart_soon():
    """Restart our own service a moment after the reply has gone out."""
    await asyncio.sleep(0.6)
    unit, verb = ACTIONS["restart"]
    code, out, err = await asyncio.to_thread(_run, ["systemctl", verb, "--no-block", "--no-ask-password", unit], 20)
    # if it worked we get stopped right about now; still here with an error = it was refused
    _state["restart_error"] = _explain(err) if code != 0 else ""


# ---------------------------------------------------------------- routes
def register(mcp, token, vault, safe):
    """Add the panel routes to the FastMCP app. `safe` is vex1_mcp._safe (keeps paths inside the vault)."""
    base = f"/{token}/panel"
    vault = pathlib.Path(vault)

    def path_of(request, want="any"):
        p = safe(request.query_params.get("path", ""))
        if any(_hidden(part) for part in p.relative_to(vault).parts):
            raise ValueError("hidden")
        if want == "dir" and not p.is_dir():
            raise ValueError("not a folder")
        if want == "file" and not p.is_file():
            raise ValueError("not a file")
        return p

    @mcp.custom_route(base, methods=["GET"])
    async def panel_page(request: Request):
        f = HERE / "vex1_panel.html"
        try:
            m = f.stat().st_mtime
            if _state["html"][0] != m:
                _state["html"] = (m, f.read_text())
        except OSError:
            return HTMLResponse("vex1_panel.html is missing - re-run the status.sh install.", status_code=500)
        return HTMLResponse(_state["html"][1], headers=HEADERS)

    @mcp.custom_route(base + "/api/sys", methods=["GET"])
    async def api_sys(request: Request):
        return _json(await asyncio.to_thread(_sys))

    @mcp.custom_route(base + "/api/ls", methods=["GET"])
    async def api_ls(request: Request):
        try:
            p = path_of(request, "dir")
        except ValueError:
            return _json({"error": "No folder there."}, 404)
        return _json(await asyncio.to_thread(_ls, p, vault))

    @mcp.custom_route(base + "/api/search", methods=["GET"])
    async def api_search(request: Request):
        q = request.query_params.get("q", "").strip()[:80]
        if len(q) < 2:
            return _json({"names": [], "text": []})
        async with _search_lock:
            return _json(await asyncio.to_thread(_search, q, vault))

    @mcp.custom_route(base + "/api/note", methods=["GET"])
    async def api_note(request: Request):
        try:
            p = path_of(request, "file")
        except ValueError:
            return _json({"error": "No file there."}, 404)
        return _json(await asyncio.to_thread(_note, p))

    @mcp.custom_route(base + "/api/pdf", methods=["GET"])
    async def api_pdf(request: Request):
        try:
            p = path_of(request, "file")
        except ValueError:
            return _json({"error": "No file there."}, 404)
        return _json({"pages": await asyncio.to_thread(_pdf_pages, p), "size": p.stat().st_size})

    @mcp.custom_route(base + "/api/pdfpage", methods=["GET"])
    async def api_pdfpage(request: Request):
        try:
            p = path_of(request, "file")
            page = max(1, min(int(request.query_params.get("page", "1")), 5000))
        except ValueError:
            return _json({"error": "No file there."}, 404)
        if p.suffix.lower() != ".pdf":
            return _json({"error": "Not a PDF."}, 400)
        async with _pdf_lock:
            img = await asyncio.to_thread(_pdf_page, p, page)
        if not img:
            return _json({"error": "Couldn't draw that page."}, 500)
        return Response(img, media_type="image/jpeg", headers={**HEADERS, "Cache-Control": "private, max-age=600"})

    @mcp.custom_route(base + "/api/raw", methods=["GET"])
    async def api_raw(request: Request):
        try:
            p = path_of(request, "file")
        except ValueError:
            return _json({"error": "No file there."}, 404)
        if p.suffix.lower() not in IMG_EXT or p.stat().st_size > RAW_MAX:
            return _json({"error": "Only images up to 12 MB can be previewed."}, 400)
        return FileResponse(p, media_type=mimetypes.guess_type(p.name)[0] or "application/octet-stream",
                            headers={**HEADERS, "Cache-Control": "private, max-age=600"})

    @mcp.custom_route(base + "/api/feed", methods=["GET"])
    async def api_feed(request: Request):
        return _json(await asyncio.to_thread(_feed, vault))

    @mcp.custom_route(base + "/api/server", methods=["GET"])
    async def api_server(request: Request):
        units, procs = await asyncio.gather(asyncio.to_thread(_units), asyncio.to_thread(_procs))
        return _json({"units": units, "procs": procs, "now": time.time()})

    @mcp.custom_route(base + "/api/logs", methods=["GET"])
    async def api_logs(request: Request):
        pats = LOG_UNITS.get(request.query_params.get("unit", "all"), LOG_UNITS["all"])

        async def gen():
            if _state["logs"] >= 4:
                yield 'data: {"m": "Too many log windows open - close one.", "u": "panel", "p": 4}\n\n'
                return
            _state["logs"] += 1
            cmd = ["journalctl", "-f", "-n", "60", "-o", "json", "--no-pager",
                   "--output-fields=MESSAGE,_SYSTEMD_UNIT,UNIT,PRIORITY"]
            for pat in pats:
                cmd += ["-u", pat]
            proc = None
            try:
                proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE,
                                                            stderr=asyncio.subprocess.DEVNULL, limit=1 << 20)
                yield "retry: 3000\n\n"
                while True:
                    try:
                        line = await asyncio.wait_for(proc.stdout.readline(), timeout=15)
                    except asyncio.TimeoutError:
                        if await request.is_disconnected():
                            break
                        yield ": ping\n\n"
                        continue
                    except ValueError:
                        continue  # one absurdly long line
                    if not line:
                        break
                    try:
                        j = json.loads(line)
                    except ValueError:
                        continue
                    msg = j.get("MESSAGE")
                    if not isinstance(msg, str) or "/panel/api/" in msg:
                        continue  # skip binary blobs and the panel's own polling
                    unit = (j.get("UNIT") or j.get("_SYSTEMD_UNIT") or "").replace(".service", "")
                    try:
                        ts = int(j.get("__REALTIME_TIMESTAMP", "0")) / 1e6
                        pri = int(j.get("PRIORITY", "6"))
                    except ValueError:
                        ts, pri = 0, 6
                    yield "data: " + json.dumps({"t": ts, "u": unit, "p": pri, "m": _redact(msg)[:600]}) + "\n\n"
            finally:
                _state["logs"] -= 1
                if proc and proc.returncode is None:
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        pass

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={**HEADERS, "Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @mcp.custom_route(base + "/api/run", methods=["GET", "POST"])
    async def api_run(request: Request):
        name = request.query_params.get("action", "")
        if name not in ACTIONS:
            return _json({"error": "Unknown action."}, 404)
        if request.method == "GET":
            return _json(await asyncio.to_thread(_run_status, name))
        if request.headers.get("x-vex1") != "1":  # a plain cross-site form/link can't send this
            return _json({"error": "Bad request."}, 400)
        last = _state["runs"].get(name)
        if last and time.time() - last["t0"] < COOLDOWN:
            return _json({"ok": False, "error": f"Easy: wait {COOLDOWN} s between presses."}, 429)
        if name == "restart":
            _state["runs"][name] = {"unit": ACTIONS[name][0], "t0": time.time()}
            _state["restart_error"] = ""
            _state["restart_task"] = asyncio.get_running_loop().create_task(_restart_soon())  # keep a reference
            return _json({"ok": True, "restarting": True, "started": STARTED})
        return _json(await asyncio.to_thread(_start, name))

"""Fast live numbers for the HUD (CPU, RAM, swap, network) as a Server-Sent Events stream.

One shared sampler reads /proc every STREAM_INTERVAL seconds (default 0.01 = 100x/s)
and only runs while at least one status page is open. CPU and network are averaged
over the last CPU_WINDOW seconds, because Linux counts CPU time in 10 ms ticks: a
10 ms reading on its own would only ever be 0% or 100%.
"""
import asyncio
import collections
import json
import os
import time

INTERVAL = max(0.005, float(os.environ.get("STREAM_INTERVAL", "0.01")))
CPU_WINDOW = float(os.environ.get("CPU_WINDOW", "0.3"))

_hub = {"clients": 0, "task": None, "sample": "{}", "event": None}


def _cpu():
    with open("/proc/stat") as f:
        p = [int(x) for x in f.readline().split()[1:]]
    idle = p[3] + (p[4] if len(p) > 4 else 0)
    return sum(p), idle


def _net():
    rx = tx = 0
    with open("/proc/net/dev") as f:
        for line in f.readlines()[2:]:
            name, data = line.split(":", 1)
            if name.strip() == "lo":
                continue
            v = data.split()
            rx += int(v[0])
            tx += int(v[8])
    return rx, tx


def _mem():
    m = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, v = line.split(":", 1)
            m[k] = int(v.split()[0])
    ram = 100 - 100 * m["MemAvailable"] / m["MemTotal"]
    st = m.get("SwapTotal", 0)
    swap = 100 * (st - m.get("SwapFree", 0)) / st if st else 0.0
    return ram, swap


async def _sampler():
    hist = collections.deque()
    try:
        while _hub["clients"] > 0:
            now = time.monotonic()
            tot, idle = _cpu()
            rx, tx = _net()
            hist.append((now, tot, idle, rx, tx))
            while len(hist) > 2 and now - hist[0][0] > CPU_WINDOW:
                hist.popleft()
            t0, tot0, idle0, rx0, tx0 = hist[0]
            dt = max(1e-6, now - t0)
            dtot = tot - tot0
            cpu = 100 * (1 - (idle - idle0) / dtot) if dtot > 0 else 0.0
            ram, swap = _mem()
            _hub["sample"] = json.dumps({
                "t": round(time.time(), 3), "cpu": round(cpu, 1), "ram": round(ram, 1), "swap": round(swap, 1),
                "rx": round((rx - rx0) / dt), "tx": round((tx - tx0) / dt), "load": round(os.getloadavg()[0], 2)})
            ev, _hub["event"] = _hub["event"], asyncio.Event()
            ev.set()
            await asyncio.sleep(max(0.0, INTERVAL - (time.monotonic() - now)))
    finally:
        _hub["task"] = None


async def stream(request):
    """Async generator of SSE lines for one open page."""
    if _hub["event"] is None:
        _hub["event"] = asyncio.Event()
    _hub["clients"] += 1
    if _hub["task"] is None:
        _hub["task"] = asyncio.create_task(_sampler())
    try:
        yield f"retry: 2000\ndata: {_hub['sample']}\n\n"
        last_check = time.monotonic()
        while True:
            ev = _hub["event"]
            try:
                await asyncio.wait_for(ev.wait(), timeout=5)
            except asyncio.TimeoutError:
                pass
            yield f"data: {_hub['sample']}\n\n"
            if time.monotonic() - last_check > 2:
                last_check = time.monotonic()
                if await request.is_disconnected():
                    break
    finally:
        _hub["clients"] -= 1

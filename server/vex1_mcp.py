"""Read-only MCP server for Neel's Vex1 vault.

Tools: search, read, list_folder. It can't write, move or delete anything,
and it can't see outside the vault folder (or into .git).

Served at  http://127.0.0.1:8765/<MCP_TOKEN>/mcp  and exposed to the internet
by Tailscale Funnel. The long random token in the path is the password.

Also serves a status page at  /<MCP_TOKEN>/status  (health checks live in vex1_status.py).

Needs mcp<2 (this uses the v1 FastMCP API). Install with the "mcp" step in micro-setup.yml.
"""
import os
import pathlib
import subprocess
import sys

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import vex1_status  # noqa: E402  (health checks, same folder)

VAULT = pathlib.Path(os.environ.get("VAULT", str(pathlib.Path.home() / "vex1"))).resolve()
TOKEN = os.environ["MCP_TOKEN"]
PORT = int(os.environ.get("MCP_PORT", "8765"))
MAX_CHARS = 20_000

mcp = FastMCP(
    "vex1",
    instructions=(
        "Neel's Vex1 Obsidian vault (first-year UofA engineering courses). "
        "Read-only. Use search first, then read the 1-2 files that match. "
        "Course folders live under 'First Year UofA V2/'. PDFs can be read page by page."
    ),
    host="127.0.0.1",
    port=PORT,
    streamable_http_path=f"/{TOKEN}/mcp",
    stateless_http=True,
    json_response=True,
    # Requests arrive through Tailscale Funnel with the public hostname, so the
    # localhost-only Host check would reject them. The secret path is the guard.
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)


def _safe(rel: str) -> pathlib.Path:
    """Resolve a vault-relative path, refusing anything outside the vault or in .git."""
    p = (VAULT / (rel or "").lstrip("/")).resolve()
    if p != VAULT and VAULT not in p.parents:
        raise ValueError("Path is outside the vault.")
    if ".git" in p.relative_to(VAULT).parts:
        raise ValueError("The .git folder is off limits.")
    return p


def _rel(p: pathlib.Path) -> str:
    return str(p.relative_to(VAULT))


def _cap(text: str) -> str:
    if len(text) > MAX_CHARS:
        return text[:MAX_CHARS] + f"\n\n[...cut off at {MAX_CHARS} characters - narrow it down]"
    return text


@mcp.tool()
def search(query: str, folder: str = "", max_results: int = 40) -> str:
    """Search the vault. Matches file NAMES and the TEXT inside notes (.md/.txt/.csv etc.),
    case-insensitive. `folder` limits the search to a vault-relative folder, e.g.
    'First Year UofA V2/Phys 130'. PDFs are matched by file name only - open them with `read`."""
    root = _safe(folder)
    if not root.is_dir():
        return f"No folder called '{folder}'."
    max_results = max(1, min(int(max_results), 200))
    q = query.lower()

    name_hits = []
    for p in root.rglob("*"):
        if ".git" in p.parts or not p.is_file():
            continue
        if q in p.name.lower():
            name_hits.append(_rel(p))
            if len(name_hits) >= max_results:
                break

    try:
        out = subprocess.run(
            ["rg", "-i", "-F", "-n", "--no-heading", "--max-count", "3", "--max-columns", "220",
             "--max-columns-preview", "-g", "!.git", "-g", "!*.pdf", "--", query, str(root)],
            capture_output=True, text=True, timeout=25,
        ).stdout
    except subprocess.TimeoutExpired:
        out = ""
    text_hits = []
    for line in out.splitlines():
        if line.startswith(str(VAULT) + "/"):
            line = line[len(str(VAULT)) + 1:]
        text_hits.append(line)
        if len(text_hits) >= max_results:
            break

    parts = []
    if name_hits:
        parts.append("FILE NAMES matching:\n" + "\n".join(name_hits))
    if text_hits:
        parts.append("TEXT matches (file:line: text):\n" + "\n".join(text_hits))
    return _cap("\n\n".join(parts)) if parts else f"Nothing found for '{query}'."


@mcp.tool()
def read(path: str, start: int = 1, count: int = 300) -> str:
    """Read a vault file by its vault-relative path. For text/markdown, `start`/`count`
    are LINE numbers. For PDFs they are PAGE numbers (default: first 10 pages)."""
    p = _safe(path)
    if not p.is_file():
        return f"No file at '{path}'. Use search or list_folder to find it."
    start = max(1, int(start))
    if p.suffix.lower() == ".pdf":
        count = max(1, min(int(count) if count != 300 else 10, 40))
        try:
            txt = subprocess.run(
                ["pdftotext", "-layout", "-f", str(start), "-l", str(start + count - 1), str(p), "-"],
                capture_output=True, text=True, timeout=60,
            ).stdout
        except subprocess.TimeoutExpired:
            return "That PDF took too long - try fewer pages."
        if not txt.strip():
            return f"Pages {start}-{start + count - 1} have no text layer (probably scanned/handwritten)."
        return _cap(f"[{_rel(p)} - pages {start}-{start + count - 1}]\n{txt}")
    try:
        lines = p.read_text(errors="replace").splitlines()
    except Exception as e:  # noqa: BLE001
        return f"Can't read that file as text ({e})."
    count = max(1, min(int(count), 2000))
    chunk = lines[start - 1:start - 1 + count]
    more = len(lines) - (start - 1 + len(chunk))
    tail = f"\n\n[{more} more lines - call read with start={start + len(chunk)}]" if more > 0 else ""
    return _cap(f"[{_rel(p)} - lines {start}-{start + len(chunk) - 1} of {len(lines)}]\n" + "\n".join(chunk) + tail)


@mcp.tool()
def list_folder(path: str = "", depth: int = 1) -> str:
    """List what's in a vault folder (vault-relative, '' = top level). depth 1-3."""
    root = _safe(path)
    if not root.is_dir():
        return f"No folder at '{path}'."
    depth = max(1, min(int(depth), 3))
    out = []

    def walk(d: pathlib.Path, level: int):
        try:
            kids = sorted(d.iterdir(), key=lambda x: (x.is_file(), x.name.lower()))
        except PermissionError:
            return
        for k in kids:
            if k.name == ".git":
                continue
            out.append("  " * (level - 1) + (k.name + "/" if k.is_dir() else k.name))
            if k.is_dir() and level < depth:
                walk(k, level + 1)

    walk(root, 1)
    return _cap(f"[{_rel(root) if root != VAULT else '(vault top)'}]\n" + "\n".join(out))


@mcp.tool()
def status() -> str:
    """Health check of Neel's vex-micro server: memory, disk, vault sync, connector,
    Tailscale/Funnel, last Canvas sync, the A1 retry loop and the last PC push."""
    return vex1_status.render_text(vex1_status.collect())


# Status page for Neel's iPad: https://<funnel host>/<MCP_TOKEN>/status  (add ?format=json for JSON)
@mcp.custom_route(f"/{TOKEN}/status", methods=["GET"])
async def status_page(request: Request):
    import anyio
    st = await anyio.to_thread.run_sync(vex1_status.collect)
    if request.query_params.get("format") == "json":
        return JSONResponse(st)
    return HTMLResponse(vex1_status.render_html(st), headers={"Cache-Control": "no-store"})


if __name__ == "__main__":
    mcp.run(transport="streamable-http")

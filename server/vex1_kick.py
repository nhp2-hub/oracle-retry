"""Start a GitHub Actions workflow in nhp2-hub/oracle-retry from vex-micro.

GitHub stopped running this repo's scheduled jobs, so systemd timers on the server
do the timing instead:  python3 vex1_kick.py oracle-a1-retry.yml 10
  -> starts the workflow unless it ran in the last 10 minutes or is already queued/running.
Needs GH_KICK_TOKEN: a fine-grained token limited to oracle-retry with Actions: read & write.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime

REPO = "nhp2-hub/oracle-retry"


def api(path, method="GET", body=None):
    req = urllib.request.Request(
        f"https://api.github.com/repos/{REPO}/{path}", method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {os.environ['GH_KICK_TOKEN']}",
                 "Accept": "application/vnd.github+json", "User-Agent": "vex1-kick",
                 "X-GitHub-Api-Version": "2022-11-28"})
    with urllib.request.urlopen(req, timeout=20) as r:
        raw = r.read()
        return json.loads(raw) if raw else {}


def main(workflow, min_gap_min):
    if not os.environ.get("GH_KICK_TOKEN"):
        print("no GH_KICK_TOKEN set - run kick setup first"); return 1
    wf = api(f"actions/workflows/{workflow}")
    if wf.get("state") != "active":
        print(f"{workflow} is {wf.get('state')} - not starting it"); return 0
    runs = api(f"actions/workflows/{workflow}/runs?per_page=5").get("workflow_runs", [])
    now = time.time()
    for r in runs:
        if r["status"] in ("queued", "in_progress", "waiting", "pending"):
            print(f"{workflow}: a run is already {r['status']} - skipping"); return 0
    if runs:
        last = datetime.fromisoformat(runs[0]["created_at"].replace("Z", "+00:00")).timestamp()
        if now - last < min_gap_min * 60:
            print(f"{workflow}: last run {int((now - last) / 60)} min ago - skipping"); return 0
    api(f"actions/workflows/{workflow}/dispatches", "POST", {"ref": "main"})
    print(f"{workflow}: started")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1], float(sys.argv[2]) if len(sys.argv) > 2 else 10))
    except urllib.error.HTTPError as e:
        print(f"GitHub said {e.code}: {e.read()[:200]!r}")
        sys.exit(1)

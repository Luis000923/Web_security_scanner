#!/usr/bin/env python3
"""run_zap_baseline.py — external OWASP ZAP baseline over the same 338-target
GET-parameter list used by the paper's own ablation sweep, graded by the same
independent oracle (tools/eval_oracle.py) against the same ground truth.

Requires a ZAP daemon already reachable at --zap-url (see the accompanying
`docker run` invocation printed by this script's header comment). Talks to
the ZAP REST API directly over HTTP (stdlib only, no zaproxy pip dependency).

Usage:
    .venv/bin/python tools/run_zap_baseline.py \
        --target-list testbed/benchmark_targets.json \
        --ground-truth testbed/ground_truth.json \
        --zap-url http://127.0.0.1:8090 \
        --out testbed/results/zap_baseline

ZAP daemon (run first, host networking so 127.0.0.1:8443 reaches the
benchmark exactly like the paper's own scanner does):
    docker run -d --name zap_baseline --network host \
        ghcr.io/zaproxy/zaproxy:stable \
        zap.sh -daemon -host 0.0.0.0 -port 8090 -config api.disablekey=true
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

import eval_oracle as oracle  # noqa: E402


def zap_get(base: str, path: str, **params) -> dict:
    qs = urllib.parse.urlencode(params)
    url = f"{base}{path}?{qs}" if qs else f"{base}{path}"
    with urllib.request.urlopen(url, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8"))


def wait_ready(base: str, timeout: float = 120) -> None:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            v = zap_get(base, "/JSON/core/view/version/")
            print(f"[zap] daemon ready, version={v.get('version')}")
            return
        except Exception:
            time.sleep(2)
    raise SystemExit("ZAP daemon never became ready")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target-list", type=Path, default=REPO_ROOT / "testbed" / "benchmark_targets.json")
    ap.add_argument("--ground-truth", type=Path, default=REPO_ROOT / "testbed" / "ground_truth.json")
    ap.add_argument("--zap-url", default="http://127.0.0.1:8090")
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "testbed" / "results" / "zap_baseline")
    ap.add_argument("--policy", default=None, help="ZAP scan policy name (default: ZAP's own default policy)")
    ap.add_argument("--poll-interval", type=float, default=3.0)
    ap.add_argument("--max-concurrent", type=int, default=8)
    args = ap.parse_args(argv)

    args.out.mkdir(parents=True, exist_ok=True)
    base = args.zap_url.rstrip("/")
    wait_ready(base)

    targets = json.loads(args.target_list.read_text())
    print(f"[zap] {len(targets)} targets")

    t_start = time.time()

    # 1) Access each URL once so ZAP's Sites tree knows about it (spider-free,
    #    exactly the entry point our own scanner uses: url?param=1).
    full_urls = []
    for t in targets:
        url = f"{t['url']}?{urllib.parse.quote(t['param'])}=1"
        full_urls.append(url)
        zap_get(base, "/JSON/core/action/accessUrl/", url=url)
    print(f"[zap] accessed {len(full_urls)} URLs, spider-free")

    # 2) Active-scan each URL individually (recurse=false keeps it scoped to
    #    exactly that URL+param, not the whole site), throttled to
    #    --max-concurrent in-flight scans so ZAP's own scanner threads aren't
    #    overrun.
    pending: dict[str, str] = {}  # scanId -> url
    done = 0
    url_iter = iter(full_urls)

    def launch_next() -> bool:
        try:
            u = next(url_iter)
        except StopIteration:
            return False
        kwargs = {"url": u, "recurse": "false", "inScopeOnly": "false"}
        if args.policy:
            kwargs["scanPolicyName"] = args.policy
        r = zap_get(base, "/JSON/ascan/action/scan/", **kwargs)
        pending[r["scan"]] = u
        return True

    for _ in range(min(args.max_concurrent, len(full_urls))):
        launch_next()

    while pending:
        for scan_id in list(pending.keys()):
            st = zap_get(base, "/JSON/ascan/view/status/", scanId=scan_id)
            if int(st["status"]) >= 100:
                done += 1
                url = pending.pop(scan_id)
                print(f"[zap] [{done}/{len(full_urls)}] done: {url}")
                launch_next()
        if pending:
            time.sleep(args.poll_interval)

    elapsed = time.time() - t_start
    print(f"[zap] all active scans complete in {elapsed:.1f}s")

    # 3) Pull every alert ZAP raised anywhere under the benchmark base URL.
    base_url = targets[0]["url"].split("/benchmark/")[0] + "/benchmark/"
    alerts_resp = zap_get(base, "/JSON/core/view/alerts/", baseurl=base_url, start=0, count=100000)
    alerts = alerts_resp.get("alerts", [])
    print(f"[zap] {len(alerts)} raw alerts")
    (args.out / "zap_alerts_raw.json").write_text(json.dumps(alerts, indent=2))

    # 4) Fold into the same (normalized_url, param, canonical_type) key space
    #    the oracle uses for our own scanner's telemetry.
    findings: set[tuple] = set()
    for a in alerts:
        url = a.get("url", "")
        param = a.get("param", "") or ""
        vtype = a.get("alert", "") or a.get("name", "")
        if not param:
            continue  # not a parameter-scoped finding (e.g. a header alert)
        key = (oracle.normalize_url(url), param, oracle.canonicalize_type(vtype))
        findings.add(key)
    print(f"[zap] {len(findings)} unique (url, param, type) findings after folding")

    gt = oracle.load_ground_truth(args.ground_truth)
    metrics = oracle.evaluate(findings, gt)
    result = metrics.as_dict()
    result["elapsed_seconds"] = round(elapsed, 1)
    result["n_targets"] = len(targets)
    result["n_raw_alerts"] = len(alerts)

    # Restricted variant: only alerts whose canonical type is one of the five
    # categories this ground truth actually scores (drops ZAP's unrelated
    # informational/header noise from the precision denominator), for a
    # stricter apples-to-apples reading against a scanner that, by design,
    # only ever reports these five categories.
    scored_types = {c for (_, _, c) in gt.all_keys}
    restricted = {f for f in findings if f[2] in scored_types}
    metrics_restricted = oracle.evaluate(restricted, gt)
    result["restricted"] = metrics_restricted.as_dict()

    (args.out / "zap_metrics.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

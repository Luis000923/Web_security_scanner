#!/usr/bin/env python3
"""reanalysis.py — reviewer-driven re-analysis of the ablation sweep.

Replaces the detection-cost analysis of analyze_results.py, which used the
run-global ``request_index`` for detected instances and ``B + 1`` for
undetected ones (two different scales). Here:

* Per-target ordinal ``k``: for each (tester, normalized url, param) group the
  telemetry rows are sorted by ``request_index`` and numbered 1..n. ``k`` is the
  position of a probe within the sequence the tester sent to that target.
* Detection cost of a vulnerable instance = smallest ``k`` of a detecting row
  (decision true, tuple in P), censored at ``Bc + 1`` where ``Bc = B`` for a
  bounded budget and ``Bc = Nmax`` (largest n over all groups and all
  configurations at that budget) for the unbounded one.
* AUC_B = (1/Bc) * sum_{k=1..Bc} c(k)/|P|.
* Tests per budget on the 194 paired instances: Friedman (5 configs), Wilcoxon
  (Pratt) baseline vs each ablation with BH within budget, McNemar exact on the
  detected indicator, Cliff's delta with 95% percentile bootstrap CI.

Also emits: confusion counts with trap hits, FP anatomy, worked example,
determinism check against a replicate sweep, latency of first vs later probes,
request volume (from ``[core] network_requests=`` in scanner.stderr.log) and
the LLM-triage audit trail.

Usage:
    python tools/reanalysis.py --results testbed/results \
        [--replicate testbed/results_rep] [--zap testbed/results/zap_baseline] \
        --out testbed/reanalysis
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from scipy import stats

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))
import eval_oracle as oracle  # noqa: E402

CONDITIONS = ["baseline", "no-interleave", "no-priority", "no-runtime-confirm",
              "no-adaptive-sorting"]
SHORT = {"baseline": "baseline", "no-interleave": "NI", "no-priority": "NP",
         "no-runtime-confirm": "NRC", "no-adaptive-sorting": "NAS",
         "ai-triage": "ai-triage"}
SLUG = {c: c.replace("-", "") for c in CONDITIONS + ["ai-triage"]}
BUDGETS = [10, 20, 50, 0]
N_BOOT = 5000
RNG = np.random.default_rng(20261118)


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------

def run_dir(results: Path, budget: int, cond: str) -> Path:
    return results / f"budget{budget}_{SLUG[cond]}"


def load_rows(d: Path) -> list[dict]:
    jsonls = sorted(d.glob("telemetry_*.jsonl"), key=lambda p: p.stat().st_mtime)
    if not jsonls:
        return []
    rows = []
    for line in jsonls[-1].read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    rows.sort(key=lambda r: r["request_index"])
    return rows


def annotate(rows: list[dict], gt: oracle.GroundTruth) -> None:
    """Add gkey (tester, url, param), tuple, k (per-target ordinal)."""
    counters: Counter = Counter()
    for r in rows:
        nurl = oracle.normalize_url(str(r.get("url", "")))
        g = (r.get("tester_id"), nurl, r.get("param"))
        counters[g] += 1
        r["_g"] = g
        r["_k"] = counters[g]
        r["_tuple"] = (nurl, r.get("param"),
                       oracle.canonicalize_type(str(r.get("tester_id") or r.get("context") or "")))
    for r in rows:
        r["_n"] = counters[r["_g"]]


def findings_of(rows: list[dict]) -> set:
    return {r["_tuple"] for r in rows if r.get("decision")}


def costs_of(rows: list[dict], gt: oracle.GroundTruth) -> dict:
    best: dict = {}
    for r in rows:
        if r.get("decision") and r["_tuple"] in gt.positives:
            t = r["_tuple"]
            if t not in best or r["_k"] < best[t]:
                best[t] = r["_k"]
    return best


def stderr_counts(d: Path) -> dict:
    out = {"network_requests": None, "confirmation_requests": None}
    log = d / "scanner.stderr.log"
    if log.exists():
        m = re.findall(r"network_requests=(\d+) confirmation_requests=(\d+)",
                       log.read_text(errors="replace"))
        if m:
            out["network_requests"] = sum(int(a) for a, _ in m)
            out["confirmation_requests"] = sum(int(b) for _, b in m)
    return out


def wall_clock(rows: list[dict]) -> float | None:
    from datetime import datetime
    if not rows:
        return None
    t0 = datetime.fromisoformat(rows[0]["timestamp"])
    t1 = datetime.fromisoformat(rows[-1]["timestamp"])
    return (t1 - t0).total_seconds()


# --------------------------------------------------------------------------
# Statistics
# --------------------------------------------------------------------------

def cliffs_delta(a: np.ndarray, b: np.ndarray) -> float:
    """P(a > b) - P(a < b); a = ablation cost, b = baseline cost."""
    diff = a[:, None] - b[None, :]
    return float((np.sum(diff > 0) - np.sum(diff < 0)) / diff.size)


def boot_ci(a: np.ndarray, b: np.ndarray) -> tuple[float, float]:
    n = len(a)
    vals = np.empty(N_BOOT)
    for i in range(N_BOOT):
        idx = RNG.integers(0, n, n)
        vals[i] = cliffs_delta(a[idx], b[idx])
    return float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))


def bh(pvals: list[float]) -> list[float]:
    m = len(pvals)
    order = np.argsort(pvals)
    adj = np.empty(m)
    prev = 1.0
    for rank, i in reversed(list(enumerate(order, start=1))):
        prev = min(prev, pvals[i] * m / rank)
        adj[i] = prev
    return adj.tolist()


def mcnemar_exact(b: int, c: int) -> float:
    n = b + c
    if n == 0:
        return 1.0
    return float(min(1.0, 2 * stats.binom.cdf(min(b, c), n, 0.5)))


def auc(costs: np.ndarray, bc: int, n_pos: int) -> float:
    ks = np.arange(1, bc + 1)
    c = np.array([(costs <= k).sum() for k in ks])
    return float(c.sum() / (bc * n_pos))


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", type=Path, default=REPO_ROOT / "testbed" / "results")
    ap.add_argument("--replicate", type=Path, default=None)
    ap.add_argument("--zap", type=Path, default=None)
    ap.add_argument("--ground-truth", type=Path,
                    default=REPO_ROOT / "testbed" / "ground_truth.json")
    ap.add_argument("--target-list", type=Path,
                    default=REPO_ROOT / "testbed" / "benchmark_targets.json")
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "testbed" / "reanalysis")
    args = ap.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)

    gt = oracle.load_ground_truth(args.ground_truth)
    pos = sorted(gt.positives)
    n_pos = len(pos)
    targets = {(oracle.normalize_url(t["url"]), t["param"])
               for t in json.loads(args.target_list.read_text())}
    scored_types = {c for (_, _, c) in gt.all_keys}

    runs: dict = {}
    for b in BUDGETS:
        for cond in CONDITIONS + ["ai-triage"]:
            d = run_dir(args.results, b, cond)
            rows = load_rows(d)
            if not rows:
                continue
            annotate(rows, gt)
            runs[(b, cond)] = {"dir": d, "rows": rows}

    summary: dict = {"confusion": [], "tests": {}, "auc": {}, "nmax": {}}

    # ---- Confusion counts -------------------------------------------------
    for (b, cond), run in sorted(runs.items()):
        H = findings_of(run["rows"])
        m = oracle.evaluate(H, gt).as_dict()
        sc = stderr_counts(run["dir"])
        raw = sum(1 for r in run["rows"] if r.get("decision"))
        summary["confusion"].append({
            "budget": b, "condition": cond, "TP": m["tp"], "FP": m["fp"],
            "trap": m["fp_on_traps"], "precision": m["precision"],
            "recall": m["recall"], "f1": m["f1_score"], "unique_tuples": len(H),
            "raw_findings": raw, "telemetry_rows": len(run["rows"]),
            "wall_clock_s": wall_clock(run["rows"]), **sc,
        })

    # ---- Detection cost per budget ---------------------------------------
    cost_mats: dict = {}
    for b in BUDGETS:
        have = [c for c in CONDITIONS if (b, c) in runs]
        if len(have) < 2 or "baseline" not in have:
            continue
        nmax = max(r["_n"] for c in have for r in runs[(b, c)]["rows"])
        bc = b if b else nmax
        summary["nmax"][b] = nmax
        mat = {}
        for c in have:
            cst = costs_of(runs[(b, c)]["rows"], gt)
            mat[c] = np.array([min(cst.get(t, bc + 1), bc + 1) for t in pos], dtype=float)
        cost_mats[b] = (bc, mat)
        summary["auc"][b] = {SHORT[c]: auc(mat[c], bc, n_pos) for c in have}

        entry: dict = {"Bc": bc}
        if len(have) >= 3:
            fr = stats.friedmanchisquare(*[mat[c] for c in have])
            entry["friedman_chi2"] = float(fr.statistic)
            entry["friedman_p"] = float(fr.pvalue)
        base = mat["baseline"]
        contrasts, pvals = [], []
        for c in have:
            if c == "baseline":
                continue
            arm = mat[c]
            if np.all(arm == base):
                p = 1.0
            else:
                p = float(stats.wilcoxon(arm, base, zero_method="pratt").pvalue)
            det_b, det_a = base <= bc, arm <= bc
            nb = int(np.sum(det_b & ~det_a))
            na = int(np.sum(~det_b & det_a))
            d = cliffs_delta(arm, base)
            lo, hi = boot_ci(arm, base)
            contrasts.append({
                "ablation": SHORT[c], "cliffs_delta": d, "ci95": [lo, hi],
                "wilcoxon_p": p, "median_cost_baseline": float(np.median(base)),
                "median_cost_ablation": float(np.median(arm)),
                "mean_cost_baseline": float(np.mean(base)),
                "mean_cost_ablation": float(np.mean(arm)),
                "n_diff": int(np.sum(arm != base)),
                "mcnemar_only_baseline": nb, "mcnemar_only_ablation": na,
                "mcnemar_p": mcnemar_exact(nb, na),
            })
            pvals.append(p)
        for ctr, padj in zip(contrasts, bh(pvals)):
            ctr["wilcoxon_p_bh"] = padj
        entry["contrasts"] = contrasts
        summary["tests"][b] = entry

    # ---- FP anatomy (B=20 baseline) --------------------------------------
    vuln_eps = {(u, p) for (u, p, _t) in gt.positives}
    trap_eps = {(u, p) for (u, p, _t) in gt.traps}
    anatomy = {}
    for key in [(20, "baseline"), (0, "baseline")]:
        if key not in runs:
            continue
        H = findings_of(runs[key]["rows"])
        fp = H - gt.positives
        cats: Counter = Counter()
        by_type: Counter = Counter()
        by_tester: Counter = Counter()
        for (u, p, t) in fp:
            if (u, p, t) in gt.traps:
                cats["trap_hit"] += 1
            elif (u, p) not in targets:
                cats["outside_targets"] += 1
            elif t not in scored_types:
                cats["unscored_type"] += 1
            elif (u, p) in vuln_eps:
                cats["scored_type_on_vuln_endpoint_wrong_type"] += 1
            elif (u, p) in trap_eps:
                cats["scored_type_on_trap_endpoint_other_type"] += 1
            else:
                cats["other"] += 1
            by_type[t] += 1
        for r in runs[key]["rows"]:
            if r.get("decision") and r["_tuple"] in fp:
                by_tester[r.get("tester_id")] += 1
        anatomy[f"B{key[0]}_{key[1]}"] = {
            "fp_total": len(fp), "categories": dict(cats),
            "fp_by_type": dict(by_type.most_common()),
            "fp_rows_by_tester": dict(by_tester.most_common()),
        }
    summary["fp_anatomy"] = anatomy

    # ---- Worked example ---------------------------------------------------
    if (20, "baseline") in runs:
        rows = runs[(20, "baseline")]["rows"]
        cst = costs_of(rows, gt)
        # pick a detected instance with cost > 1 so the example is informative
        pick = next((t for t in pos if cst.get(t, 99) > 1 and t in cst), None) \
            or next((t for t in pos if t in cst), None)
        if pick:
            ex = [r for r in rows if r["_tuple"] == pick]
            summary["worked_example"] = {
                "instance": list(pick), "cost_k": cst[pick],
                "rows": [{"request_index": r["request_index"], "k": r["_k"],
                          "payload_id": r.get("payload_id"), "decision": r.get("decision"),
                          "tester_id": r.get("tester_id")} for r in ex[: cst[pick] + 1]],
            }

    # ---- Determinism vs replicate ----------------------------------------
    if args.replicate:
        det = []
        for (b, cond), run in sorted(runs.items()):
            d2 = run_dir(args.replicate, b, cond)
            rows2 = load_rows(d2)
            if not rows2:
                continue
            annotate(rows2, gt)
            seq1, seq2 = defaultdict(list), defaultdict(list)
            for r in run["rows"]:
                seq1[r["_g"]].append(r.get("payload_id"))
            for r in rows2:
                seq2[r["_g"]].append(r.get("payload_id"))
            keys = set(seq1) | set(seq2)
            same = sum(1 for g in keys if seq1.get(g) == seq2.get(g))
            dec1 = {(r["_g"], r["_k"]) for r in run["rows"] if r.get("decision")}
            dec2 = {(r["_g"], r["_k"]) for r in rows2 if r.get("decision")}
            m1 = oracle.evaluate(findings_of(run["rows"]), gt).as_dict()
            m2 = oracle.evaluate(findings_of(rows2), gt).as_dict()
            det.append({
                "budget": b, "condition": cond, "groups": len(keys),
                "identical_sequences": same, "pct_identical": 100.0 * same / len(keys),
                "decision_mismatches": len(dec1 ^ dec2),
                "TP": [m1["tp"], m2["tp"]], "FP": [m1["fp"], m2["fp"]],
                "trap": [m1["fp_on_traps"], m2["fp_on_traps"]],
                "findings_symdiff": sorted(map(list, findings_of(run["rows"]) ^ findings_of(rows2))),
                "wall_clock_s": [wall_clock(run["rows"]), wall_clock(rows2)],
            })
        summary["determinism"] = det

    # ---- Latency: first probe per target vs later ------------------------
    lat = {}
    for key in [(20, "baseline"), (0, "baseline")]:
        if key not in runs:
            continue
        rows = [r for r in runs[key]["rows"] if r.get("vector") == "getparam"]
        first = np.array([r["elapsed_time"] for r in rows if r["_k"] == 1], dtype=float)
        later = np.array([r["elapsed_time"] for r in rows if r["_k"] > 1], dtype=float)
        if len(first) and len(later):
            lat[f"B{key[0]}"] = {
                "first_p50": float(np.percentile(first, 50)), "first_p99": float(np.percentile(first, 99)),
                "later_p50": float(np.percentile(later, 50)), "later_p99": float(np.percentile(later, 99)),
                "n_first": len(first), "n_later": len(later),
            }
    summary["latency"] = lat

    # ---- LLM triage audit -------------------------------------------------
    triage = []
    for b in BUDGETS:
        key = (b, "ai-triage")
        if key not in runs:
            continue
        reports = sorted((runs[key]["dir"] / "report").glob("scan_*.json"))
        reports = [p for p in reports if "enriched" not in p.name]
        block = oracle.load_ai_triage(reports[-1]) if reports else None
        entry = {"budget": b, "block_found": block is not None}
        if block:
            dec = block.get("decisions") or []
            scores = [float(d.get("confidence") or d.get("ai_confidence") or 0) for d in dec]
            verdicts = Counter(str(d.get("ai_verdict") or d.get("verdict")) for d in dec)
            H = findings_of(runs[key]["rows"])
            # Telemetry is written before triage, so H is the pre-triage set.
            # The post-triage set drops every suppressed tuple that no kept
            # decision re-reported; grading against H would hide lost TPs.
            def _key(d: dict) -> tuple:
                return oracle._finding_key(d.get("url", ""), d.get("parameter") or d.get("param"),
                                           d.get("type", ""))
            dropped = {_key(d) for d in dec if d.get("dropped")}
            kept = {_key(d) for d in dec if not d.get("dropped")}
            post = H - (dropped - kept)
            am = oracle.evaluate_ai_triage(block, post, gt).as_dict()
            m_pre, m_post = oracle.evaluate(H, gt), oracle.evaluate(post, gt)
            entry["pre"] = {"TP": len(m_pre.tp), "FP": len(m_pre.fp), "trap": len(m_pre.fp_on_traps),
                            "precision": m_pre.precision, "recall": m_pre.recall}
            entry["post"] = {"TP": len(m_post.tp), "FP": len(m_post.fp), "trap": len(m_post.fp_on_traps),
                             "precision": m_post.precision, "recall": m_post.recall}
            entry["dropped_tuples_outside_scored_set"] = len(
                (dropped - kept) - m_pre.tp - m_pre.fp)
            entry.update({
                "candidates": int(block.get("total_candidates_triaged", len(dec))),
                "decisions_logged": len(dec), "verdicts": dict(verdicts),
                "fallbacks": sum(1 for d in dec if d.get("fallback") or d.get("error")),
                "score_median": float(np.median(scores)) if scores else None,
                "score_p95": float(np.percentile(scores, 95)) if scores else None,
                "score_max": float(max(scores)) if scores else None,
                "n_score_gt_0_5": sum(1 for s in scores if s > 0.5),
                "backend": block.get("backend"), "model": block.get("model"),
                "keys": sorted(block.keys()), **am,
            })
        triage.append(entry)
    summary["ai_triage"] = triage

    # ---- ZAP ----------------------------------------------------------------
    if args.zap and (args.zap / "zap_metrics.json").exists():
        zm = json.loads((args.zap / "zap_metrics.json").read_text())
        ztuples = {tuple(t) for t in json.loads((args.zap / "zap_tuples.json").read_text())}
        z_tp = ztuples & gt.positives
        w_tp = findings_of(runs[(20, "baseline")]["rows"]) & gt.positives if (20, "baseline") in runs else set()
        summary["zap"] = {
            "metrics": zm, "zap_tp": len(z_tp), "wss_b20_tp": len(w_tp),
            "common": len(z_tp & w_tp), "only_zap": len(z_tp - w_tp),
            "only_wss": len(w_tp - z_tp),
            "unique_tuples_all": len(ztuples),
            "unique_tuples_scored": len({t for t in ztuples if t[2] in scored_types}),
        }

    # ---- Outputs ------------------------------------------------------------
    (args.out / "reanalysis.json").write_text(json.dumps(summary, indent=2, default=str))
    with (args.out / "tests_per_budget.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["budget", "Bc", "ablation", "cliffs_delta", "ci_lo", "ci_hi",
                    "wilcoxon_p", "wilcoxon_p_bh", "median_base", "median_abl",
                    "n_diff", "mcnemar_only_base", "mcnemar_only_abl", "mcnemar_p",
                    "friedman_p"])
        for b, e in summary["tests"].items():
            for c in e["contrasts"]:
                w.writerow([b, e["Bc"], c["ablation"], c["cliffs_delta"], *c["ci95"],
                            c["wilcoxon_p"], c["wilcoxon_p_bh"], c["median_cost_baseline"],
                            c["median_cost_ablation"], c["n_diff"],
                            c["mcnemar_only_baseline"], c["mcnemar_only_ablation"],
                            c["mcnemar_p"], e.get("friedman_p")])

    # Figure 3: recall by probe ordinal at B=20 and unbounded.
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        panels = [b for b in (20, 0) if b in cost_mats]
        if panels:
            fig, axes = plt.subplots(1, len(panels), figsize=(3.5 * len(panels), 2.6),
                                     sharey=True, squeeze=False)
            for ax, b in zip(axes[0], panels):
                bc, mat = cost_mats[b]
                ks = np.arange(0, bc + 1)
                for c, arr in mat.items():
                    ax.step(ks, [(arr <= k).sum() / n_pos for k in ks], where="post",
                            label=SHORT[c], linewidth=1)
                ax.set_title(f"B = {b if b else '∞'}", fontsize=9)
                ax.set_xlabel("per-target probe ordinal k", fontsize=8)
                ax.grid(alpha=.3)
                if b == 0:
                    ax.set_xscale("symlog", linthresh=20)
            axes[0][0].set_ylabel("recall c(k)/|P|", fontsize=8)
            axes[0][-1].legend(fontsize=7, loc="lower right")
            fig.tight_layout()
            fig.savefig(args.out / "fig3_recall_by_probe.png", dpi=300)
            fig.savefig(args.out / "fig3_recall_by_probe.pdf")
    except Exception as exc:  # figure is optional
        print(f"[reanalysis] figure skipped: {exc}", file=sys.stderr)

    print(json.dumps({k: summary[k] for k in ("confusion", "auc", "nmax")}, indent=1,
                     default=str)[:6000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""analyze_results.py — statistical analysis + publication figures for the
payload-scheduling ablation study.

Consumes the artefacts produced by ``tools/run_experiments.py``:

    testbed/experiment_results.csv                  one graded row per run
    testbed/results/budget<B>_<slug>/*.jsonl        per-request telemetry
    testbed/ground_truth.json                       (url, param, type) labels

and produces:

    testbed/analysis/summary_by_run.csv             per-run metrics + AUC + First-TP
    testbed/analysis/detection_cost_matrix.csv      per-GT-instance x condition
    testbed/analysis/stats.json                     Friedman / post-hoc / effect sizes
    testbed/analysis/early_recall.json              Phase 3.3: First-TP cost,
                                                    adaptive (baseline) vs static
                                                    (no-adaptive-sorting), paired
                                                    Wilcoxon + Cliff's delta
    paper/figures/fig1_detection_vs_budget.{pdf,png}
    paper/figures/fig2_ablation_impact.{pdf,png}
    paper/figures/fig3_cd_diagram.{pdf,png}         (if a complete block exists)
    paper/figures/fig4_first_tp_ecdf.{pdf,png}      (if the adaptive/static pair ran)

------------------------------------------------------------------------------
DESIGN NOTES
------------------------------------------------------------------------------
* A telemetry row is a *request*. It counts as a **true-positive detection**
  when ``decision is True`` and its ``(normalized_url, param, canonical_type)``
  key — folded with the very same helpers ``tools/eval_oracle.py`` uses — is a
  vulnerable record in the ground truth. Each GT instance is credited once, at
  the ``request_index`` of its first hit ("detection cost").

* The detection-vs-cost curve is the count of unique GT instances detected as a
  function of ``request_index``. Its area, taken on the normalised axes
  (recall vs fraction-of-budget), is reported as ``auc`` and equals mean recall
  over the budget.

* Statistical blocking unit = **per-GT-instance detection cost** (censored at
  ``budget + 1`` when never detected). For every budget at which all four
  conditions ran, we compare the four cost vectors with a Friedman test,
  Nemenyi post-hoc, and baseline-vs-ablation Wilcoxon signed-rank +
  McNemar tests with Benjamini-Hochberg correction across the pairs, plus
  Cliff's delta as a non-parametric effect size.

Run inside the project venv:  .venv/bin/python tools/analyze_results.py
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import warnings
from dataclasses import dataclass, asdict
from pathlib import Path

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

import eval_oracle as oracle  # noqa: E402  (normalize_url, canonicalize_type, load_ground_truth)

CONDITIONS = ["baseline", "no-interleave", "no-priority", "no-runtime-confirm"]
COND_LABELS = {
    "baseline": "Baseline (all on)",
    "no-interleave": "No interleave",
    "no-priority": "No priority",
    "no-runtime-confirm": "No runtime-confirm",
}

# Phase 3.3 — the adaptive-vs-static contrast. `baseline` already runs the live
# heuristic loop; `no-adaptive-sorting` pins the a-priori order. This pair is
# analysed on its own (First-TP / early-recall), *outside* the 4-arm Friedman
# ablation family above, so adding it never changes the CD-diagram block.
ADAPTIVE_CONDITION = "no-adaptive-sorting"
ADAPTIVE_PAIR = ("baseline", ADAPTIVE_CONDITION)
ADAPTIVE_PAIR_LABELS_ES = {
    "baseline": "Adaptativo (Fase 3)",
    "no-adaptive-sorting": "Estático (a priori)",
}

# run_experiments.py builds dir tags as f"budget{B}_{condition.replace('-','')}"
SLUG_TO_CONDITION = {c.replace("-", ""): c
                     for c in (*CONDITIONS, ADAPTIVE_CONDITION)}


# ---------------------------------------------------------------------------
# TASK 1 — discovery, telemetry loading, per-run metrics
# ---------------------------------------------------------------------------

@dataclass
class RunInfo:
    budget: int
    condition: str
    run_dir: Path
    jsonl: Path | None


def discover_runs(results_dir: Path) -> list[RunInfo]:
    runs: list[RunInfo] = []
    for d in sorted(results_dir.glob("budget*_*")):
        if not d.is_dir():
            continue
        stem = d.name[len("budget"):]
        budget_str, _, slug = stem.partition("_")
        try:
            budget = int(budget_str)
        except ValueError:
            warnings.warn(f"skip unparseable run dir: {d.name}")
            continue
        condition = SLUG_TO_CONDITION.get(slug)
        if condition is None:
            warnings.warn(f"skip unknown condition slug {slug!r} in {d.name}")
            continue
        jsonls = sorted(d.glob("*.jsonl"), key=lambda p: p.stat().st_mtime)
        runs.append(RunInfo(budget, condition, d, jsonls[-1] if jsonls else None))
    return runs


def load_telemetry(jsonl: Path) -> pd.DataFrame:
    rows = []
    for line in jsonl.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            warnings.warn(f"bad JSONL line in {jsonl}")
    df = pd.DataFrame(rows)
    if df.empty:
        return df
    df = df.sort_values("request_index").reset_index(drop=True)
    for col in ("decision", "confidence_final", "elapsed_time", "context"):
        if col not in df.columns:
            df[col] = np.nan
    return df


def label_detections(df: pd.DataFrame, gt: "oracle.GroundTruth") -> pd.DataFrame:
    """Add gt_key / is_tp / is_trap_hit columns using the oracle's folding."""
    if df.empty:
        return df
    keys, is_tp, is_trap = [], [], []
    for _, r in df.iterrows():
        # tester_id folds onto the same bucket as the GT "type" field.
        key = (
            oracle.normalize_url(str(r.get("url", ""))),
            r.get("param"),
            oracle.canonicalize_type(str(r.get("tester_id", ""))),
        )
        decided = bool(r.get("decision"))
        keys.append(key)
        is_tp.append(decided and key in gt.positives)
        is_trap.append(decided and key in gt.traps)
    df = df.copy()
    df["gt_key"] = keys
    df["is_tp"] = is_tp
    df["is_trap_hit"] = is_trap
    return df


def detection_cost(df: pd.DataFrame) -> dict:
    """gt_key -> request_index of first TP hit (int)."""
    if df.empty:
        return {}
    hits = df[df["is_tp"]]
    return (
        hits.groupby("gt_key")["request_index"].min().astype(int).to_dict()
    )


def cumulative_curve(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    """Step curve: x = request_index, y = # unique GT instances detected so far."""
    if df.empty:
        return np.array([0]), np.array([0])
    order = df.sort_values("request_index")
    seen: set = set()
    xs, ys = [0], [0]
    for _, r in order.iterrows():
        if r["is_tp"] and r["gt_key"] not in seen:
            seen.add(r["gt_key"])
        xs.append(int(r["request_index"]))
        ys.append(len(seen))
    return np.asarray(xs), np.asarray(ys)


def normalized_auc(xs: np.ndarray, ys: np.ndarray, total_pos: int) -> float:
    if total_pos <= 0 or len(xs) < 2 or xs.max() == xs.min():
        return float("nan")
    x = (xs - xs.min()) / (xs.max() - xs.min())
    y = ys / total_pos
    trapz = getattr(np, "trapezoid", None) or np.trapz
    return float(trapz(y, x))


def build_summary(runs: list[RunInfo], gt: "oracle.GroundTruth",
                  csv_path: Path) -> tuple[pd.DataFrame, dict]:
    total_pos = len(gt.positives)
    total_traps = len(gt.traps)
    per_run_costs: dict[tuple[int, str], dict] = {}
    records = []
    for run in runs:
        rec = {
            "budget": run.budget, "condition": run.condition,
            "n_requests": 0, "tp_unique": 0, "trap_hits": 0,
            "recall": float("nan"), "fpr": float("nan"), "auc": float("nan"),
            "first_tp": float("nan"), "mean_first_tp": float("nan"),
        }
        if run.jsonl is not None:
            df = label_detections(load_telemetry(run.jsonl), gt)
            if not df.empty:
                costs = detection_cost(df)
                per_run_costs[(run.budget, run.condition)] = costs
                xs, ys = cumulative_curve(df)
                rec.update(
                    n_requests=int(df["request_index"].max()),
                    tp_unique=len(costs),
                    trap_hits=int(df["is_trap_hit"].sum()),
                    recall=len(costs) / total_pos if total_pos else float("nan"),
                    # First-TP request index (cost to the very first detection)
                    # and the mean per-instance detection cost over what was found.
                    first_tp=min(costs.values()) if costs else float("nan"),
                    mean_first_tp=(float(np.mean(list(costs.values())))
                                   if costs else float("nan")),
                    fpr=(df.loc[df["is_trap_hit"]].groupby("gt_key").ngroups
                         / total_traps) if total_traps else float("nan"),
                    auc=normalized_auc(xs, ys, total_pos),
                )
        records.append(rec)

    summary = pd.DataFrame.from_records(records)

    # Fold in the oracle's graded CSV (authoritative TP/FP/FN) where present.
    if csv_path.exists():
        graded = pd.read_csv(csv_path)
        graded = graded.rename(columns=str.lower)
        keep = [c for c in ("budget", "condition", "tp", "fp", "fn",
                            "precision", "f1") if c in graded.columns]
        graded = graded[keep].drop_duplicates(["budget", "condition"], keep="last")
        summary = summary.merge(graded, on=["budget", "condition"], how="left",
                                suffixes=("", "_oracle"))

    meta = {
        "total_positives": total_pos, "total_traps": total_traps,
        "per_run_costs": per_run_costs,
    }
    return summary, meta


# ---------------------------------------------------------------------------
# TASK 2 — significance tests + effect sizes
# ---------------------------------------------------------------------------

def cliffs_delta(a, b) -> tuple[float, str]:
    """Cliff's delta of a vs b. delta > 0  =>  a tends to exceed b."""
    a = np.asarray(a, dtype=float)
    b = np.asarray(b, dtype=float)
    if len(a) == 0 or len(b) == 0:
        return float("nan"), "n/a"
    diff = np.sign(a[:, None] - b[None, :])
    d = float(diff.sum() / (len(a) * len(b)))
    ad = abs(d)
    mag = ("negligible" if ad < 0.147 else "small" if ad < 0.33
           else "medium" if ad < 0.474 else "large")
    return d, mag


def cost_matrix_for_budget(budget: int, per_run_costs: dict,
                           gt: "oracle.GroundTruth") -> pd.DataFrame | None:
    """Rows = every vulnerable GT instance; cols = conditions; value = detection
    cost (request_index of first hit), censored at budget+1 when never found.
    Returns None unless all four conditions ran at this budget."""
    have = [c for c in CONDITIONS if (budget, c) in per_run_costs]
    if len(have) < len(CONDITIONS):
        return None
    censored = (budget if budget > 0 else 10_000) + 1
    data = {}
    for cond in CONDITIONS:
        costs = per_run_costs[(budget, cond)]
        data[cond] = [costs.get(k, censored) for k in sorted(gt.positives)]
    return pd.DataFrame(data, index=[str(k) for k in sorted(gt.positives)])


def run_stats(meta: dict, gt: "oracle.GroundTruth") -> dict:
    from scipy.stats import friedmanchisquare, wilcoxon
    from statsmodels.stats.multitest import multipletests
    try:
        from statsmodels.stats.contingency_tables import mcnemar
    except Exception:  # pragma: no cover
        mcnemar = None
    try:
        import scikit_posthocs as sph
    except Exception:  # pragma: no cover
        sph = None

    per_run_costs = meta["per_run_costs"]
    budgets = sorted({b for (b, _c) in per_run_costs})
    out: dict = {"per_budget": {}, "pooled": None, "notes": []}

    pooled_frames = []
    for budget in budgets:
        mat = cost_matrix_for_budget(budget, per_run_costs, gt)
        if mat is None:
            out["notes"].append(f"budget {budget}: incomplete block, skipped")
            continue
        pooled_frames.append(mat)
        out["per_budget"][str(budget)] = _block_tests(
            mat, friedmanchisquare, wilcoxon, multipletests, mcnemar, sph, budget)

    if pooled_frames:
        pooled = pd.concat(pooled_frames, ignore_index=True)
        out["pooled"] = _block_tests(
            pooled, friedmanchisquare, wilcoxon, multipletests, mcnemar, sph, None)
    else:
        out["notes"].append(
            "No budget has all four conditions present — need a complete sweep "
            "before Friedman/post-hoc can run.")
    return out


def average_ranks(mat: pd.DataFrame) -> dict:
    """Friedman average ranks over the conditions (lower cost -> rank 1 -> better).

    ``mat`` has one row per GT instance and one column per condition holding the
    detection cost. This is exactly the ranking that ``friedmanchisquare`` and
    the Nemenyi post-hoc operate on, and the x-axis of a CD diagram.
    """
    from scipy.stats import rankdata
    m = mat[CONDITIONS].to_numpy(dtype=float)
    ranks = np.vstack([rankdata(row) for row in m])       # per-instance ranks
    return {c: float(ranks[:, i].mean()) for i, c in enumerate(CONDITIONS)}


def _block_tests(mat: pd.DataFrame, friedmanchisquare, wilcoxon,
                 multipletests, mcnemar, sph, budget) -> dict:
    cols = [mat[c].to_numpy(dtype=float) for c in CONDITIONS]
    res: dict = {"n_instances": int(len(mat)),
                 "avg_ranks": average_ranks(mat)}

    # Friedman across the four conditions.
    if len(mat) >= 2 and any(np.ptp(np.vstack(cols), axis=0).sum() for _ in [0]):
        try:
            stat, p = friedmanchisquare(*cols)
            res["friedman"] = {"statistic": float(stat), "p_value": float(p)}
        except ValueError as e:
            res["friedman"] = {"error": str(e)}
    else:
        res["friedman"] = {"error": "insufficient variation"}

    # Nemenyi post-hoc (conditions x conditions p-values).
    if sph is not None and len(mat) >= 2:
        try:
            nem = sph.posthoc_nemenyi_friedman(mat[CONDITIONS].to_numpy())
            nem.index = nem.columns = CONDITIONS
            res["nemenyi"] = nem.round(5).to_dict()
        except Exception as e:  # pragma: no cover
            res["nemenyi"] = {"error": str(e)}

    # Baseline vs each ablation: Wilcoxon signed-rank + McNemar, BH-corrected.
    base = mat["baseline"].to_numpy(dtype=float)
    pairs, raw_p = [], []
    detail = {}
    for cond in CONDITIONS[1:]:
        arm = mat[cond].to_numpy(dtype=float)
        entry = {}
        try:
            w_stat, w_p = wilcoxon(base, arm, zero_method="zsplit")
            entry["wilcoxon"] = {"statistic": float(w_stat), "p_value": float(w_p)}
            raw_p.append(float(w_p))
        except ValueError as e:
            entry["wilcoxon"] = {"error": str(e)}
            raw_p.append(1.0)
        pairs.append(cond)

        # McNemar on the detected/not-detected indicator (cost below censor).
        censor = mat.to_numpy().max()
        b_hit = base < censor
        a_hit = arm < censor
        if mcnemar is not None:
            n01 = int(np.sum(b_hit & ~a_hit))
            n10 = int(np.sum(~b_hit & a_hit))
            try:
                m = mcnemar([[0, n01], [n10, 0]], exact=True)
                entry["mcnemar"] = {"n_base_only": n01, "n_arm_only": n10,
                                    "p_value": float(m.pvalue)}
            except Exception as e:  # pragma: no cover
                entry["mcnemar"] = {"error": str(e)}

        d, mag = cliffs_delta(arm, base)  # arm cost > baseline cost => delta > 0
        entry["cliffs_delta"] = {"delta": d, "magnitude": mag,
                                 "interpretation": "positive => ablation is slower/worse"}
        entry["mean_cost_baseline"] = float(np.mean(base))
        entry["mean_cost_arm"] = float(np.mean(arm))
        entry["recall_baseline"] = float(np.mean(b_hit))
        entry["recall_arm"] = float(np.mean(a_hit))
        detail[cond] = entry

    if raw_p:
        rej, p_adj, *_ = multipletests(raw_p, method="fdr_bh")
        for cond, r, pa in zip(pairs, rej, p_adj):
            detail[cond]["wilcoxon"]["p_value_bh"] = float(pa)
            detail[cond]["wilcoxon"]["reject_h0_bh"] = bool(r)

    res["baseline_vs_ablation"] = detail
    return res


# ---------------------------------------------------------------------------
# TASK 2b — Phase 3.3 early-recall / First-TP cost (adaptive vs static)
# ---------------------------------------------------------------------------

def _first_tp_block(base_costs: list[float], arm_costs: list[float],
                    base_hit: list[bool], arm_hit: list[bool]) -> dict:
    """Compare per-GT-instance detection cost: ``baseline`` (adaptive) vs
    ``no-adaptive-sorting`` (static a-priori order).

    ``*_costs`` are the ``request_index`` of the first true-positive for each
    vulnerable GT instance, censored (see caller) when never found; ``*_hit``
    flags whether that instance was actually detected at all. The paired stats
    run on the instances **both** arms detected (a defined first-TP index for
    each); recall deltas use every instance.
    """
    from scipy.stats import wilcoxon

    b = np.asarray(base_costs, dtype=float)
    a = np.asarray(arm_costs, dtype=float)
    bh = np.asarray(base_hit, dtype=bool)
    ah = np.asarray(arm_hit, dtype=bool)
    both = bh & ah

    res: dict = {
        "n_instances": int(len(b)),
        "n_detected_by_both": int(both.sum()),
        "recall_adaptive": float(bh.mean()) if len(bh) else float("nan"),
        "recall_static": float(ah.mean()) if len(ah) else float("nan"),
    }
    if both.any():
        bc, ac = b[both], a[both]
        mean_ad, mean_st = float(bc.mean()), float(ac.mean())
        res.update(
            mean_first_tp_adaptive=mean_ad,
            mean_first_tp_static=mean_st,
            median_first_tp_adaptive=float(np.median(bc)),
            median_first_tp_static=float(np.median(ac)),
            # requests *saved* per detection by the feedback loop, and the %.
            requests_saved_mean=mean_st - mean_ad,
            pct_reduction=((mean_st - mean_ad) / mean_st) if mean_st else float("nan"),
        )
        d, mag = cliffs_delta(ac, bc)  # static cost > adaptive cost => delta > 0
        res["cliffs_delta"] = {"delta": d, "magnitude": mag,
                               "interpretation": "positive => adaptive finds it "
                                                 "in fewer requests"}
        diff = ac - bc
        if np.any(diff != 0):
            try:
                w_stat, w_p = wilcoxon(bc, ac, zero_method="zsplit")
                res["wilcoxon"] = {"statistic": float(w_stat), "p_value": float(w_p)}
            except ValueError as e:  # pragma: no cover - degenerate block
                res["wilcoxon"] = {"error": str(e)}
        else:
            res["wilcoxon"] = {"error": "identical cost vectors"}
    return res


def first_tp_analysis(meta: dict, gt: "oracle.GroundTruth") -> dict:
    """Early-recall study for the Phase 3 feedback loop.

    For every budget at which both ``baseline`` and ``no-adaptive-sorting`` ran,
    pair the per-instance First-TP request index and quantify how much sooner
    the adaptive scheduler reaches each vulnerability. Also pools across budgets.
    """
    per = meta["per_run_costs"]
    budgets = sorted({b for (b, _c) in per})
    out: dict = {"per_budget": {}, "pooled": None, "notes": []}
    keys = sorted(gt.positives)

    pooled = {"b": [], "a": [], "bh": [], "ah": []}
    for budget in budgets:
        base = per.get((budget, "baseline"))
        arm = per.get((budget, ADAPTIVE_CONDITION))
        if base is None or arm is None:
            out["notes"].append(
                f"budget {budget}: need both 'baseline' and '{ADAPTIVE_CONDITION}' "
                f"runs — skipped")
            continue
        censor = (budget if budget > 0 else 10_000) + 1
        bc = [base.get(k, censor) for k in keys]
        ac = [arm.get(k, censor) for k in keys]
        bh = [k in base for k in keys]
        ah = [k in arm for k in keys]
        out["per_budget"][str(budget)] = _first_tp_block(bc, ac, bh, ah)
        pooled["b"] += bc
        pooled["a"] += ac
        pooled["bh"] += bh
        pooled["ah"] += ah

    if pooled["b"]:
        out["pooled"] = _first_tp_block(pooled["b"], pooled["a"],
                                        pooled["bh"], pooled["ah"])
    elif not out["notes"]:
        out["notes"].append("no run pairs found for the adaptive-vs-static contrast")
    return out


# ---------------------------------------------------------------------------
# TASK 3 — publication figures
# ---------------------------------------------------------------------------

def _academic_style():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import seaborn as sns
    sns.set_theme(context="paper", style="whitegrid",
                  font="DejaVu Serif", rc={
                      "axes.edgecolor": "0.3", "axes.linewidth": 0.8,
                      "grid.linewidth": 0.4, "grid.color": "0.85",
                      "figure.dpi": 150, "savefig.bbox": "tight",
                  })
    return plt, sns


def _save(fig, fig_dir: Path, name: str):
    fig_dir.mkdir(parents=True, exist_ok=True)
    for ext in ("pdf", "png"):
        fig.savefig(fig_dir / f"{name}.{ext}", dpi=300)
    print(f"  wrote {fig_dir / name}.pdf / .png")


_COND_LABELS_ES = {
    "baseline": "Baseline (todo activo)",
    "no-interleave": "Sin entrelazado",
    "no-priority": "Sin priorización",
    "no-runtime-confirm": "Sin confirmación runtime",
}
# Orden del eje de presupuesto: crecientes y ∞ (presupuesto 0) al final.
_BUDGET_ORDER = [10, 20, 50, 0]
_BUDGET_TICK = {10: "10", 20: "20", 50: "50", 0: "∞"}


def fig1_detection_vs_budget(summary: pd.DataFrame, fig_dir: Path):
    plt, sns = _academic_style()
    df = summary.dropna(subset=["recall"]).copy()
    if df.empty:
        print("  fig1: no recall data yet — skipped")
        return
    # Eje X categórico y ordenado para que ∞ (presupuesto ilimitado) quede a
    # la derecha en lugar de a la izquierda como si fuera el menor presupuesto.
    present = [b for b in _BUDGET_ORDER if b in set(df["budget"])]
    xpos = {b: i for i, b in enumerate(present)}
    df["x"] = df["budget"].map(xpos)
    df["Condición"] = df["condition"].map(_COND_LABELS_ES)
    order_lbl = [_COND_LABELS_ES[c] for c in CONDITIONS]

    fig, ax = plt.subplots(figsize=(5.2, 3.4))
    palette = dict(zip(order_lbl, sns.color_palette("colorblind", 4)))
    for lbl in order_lbl:
        g = df[df["Condición"] == lbl].sort_values("x")
        if g.empty:
            continue
        ax.plot(g["x"], g["recall"], marker="o", ms=5, lw=1.6,
                color=palette[lbl], label=lbl)
    ax.set_xticks(list(xpos.values()))
    ax.set_xticklabels([_BUDGET_TICK[b] for b in present])
    ax.set_xlabel("Presupuesto de peticiones (--max-payloads; ∞ = sin límite)")
    ax.set_ylabel("Exhaustividad (TP únicos / total vulnerable)")
    ax.set_ylim(0, 1)
    ax.set_title("Exhaustividad de detección frente al presupuesto", fontsize=10, pad=8)
    ax.legend(title="", frameon=False, fontsize=8, loc="lower right")
    sns.despine(ax=ax)
    _save(fig, fig_dir, "fig1_detection_vs_budget")
    plt.close(fig)


def fig2_ablation_impact(summary: pd.DataFrame, fig_dir: Path):
    plt, sns = _academic_style()
    piv_r = summary.pivot_table(index="budget", columns="condition", values="recall")
    piv_f = summary.pivot_table(index="budget", columns="condition", values="fpr")
    if "baseline" not in piv_r.columns or piv_r.dropna(how="all").empty:
        print("  fig2: need baseline + ablation recall — skipped")
        return
    budgets_present = [b for b in _BUDGET_ORDER if b in piv_r.index]
    rows = []
    for budget in budgets_present:
        for cond in CONDITIONS[1:]:
            if cond not in piv_r.columns:
                continue
            rows.append({
                "budget": _BUDGET_TICK[budget],
                "Ablación": _COND_LABELS_ES[cond],
                "Δ Exhaustividad (baseline − ablación)":
                    piv_r.loc[budget, "baseline"] - piv_r.loc[budget, cond],
                "Δ FPR (ablación − baseline)":
                    (piv_f.loc[budget, cond] - piv_f.loc[budget, "baseline"])
                    if "baseline" in piv_f.columns else np.nan,
            })
    d = pd.DataFrame(rows)
    if d.empty:
        print("  fig2: no ablation pairs — skipped")
        return
    order_x = [_BUDGET_TICK[b] for b in budgets_present]
    hue_order = [_COND_LABELS_ES[c] for c in CONDITIONS[1:]]
    m_rec = "Δ Exhaustividad (baseline − ablación)"

    # La Δ FPR es idénticamente ~0 en todas las celdas (ver tabla), por lo que
    # se reporta en prosa y solo se grafica la Δ exhaustividad.
    fig, ax = plt.subplots(figsize=(5.4, 3.4))
    pal = sns.color_palette("colorblind", len(CONDITIONS) - 1)
    sns.barplot(data=d, x="budget", y=m_rec, hue="Ablación",
                order=order_x, hue_order=hue_order, palette=pal, ax=ax)
    ax.axhline(0, color="0.3", linewidth=0.8)
    ax.set_xlabel("Presupuesto de peticiones (∞ = sin límite)")
    ax.set_ylabel("Δ Exhaustividad\n(baseline − ablación)")
    ax.set_title("Impacto de desactivar cada optimización", fontsize=10, pad=8)
    ax.legend(title="", frameon=False, fontsize=8, loc="upper right")
    sns.despine(ax=ax)
    _save(fig, fig_dir, "fig2_ablation_impact")
    plt.close(fig)


def fig3_cd_diagram(stats: dict, fig_dir: Path):
    try:
        import scikit_posthocs as sph
    except Exception:
        print("  fig3: scikit-posthocs unavailable — skipped")
        return
    block = stats.get("pooled") or next(iter(stats.get("per_budget", {}).values()), None)
    if not block:
        print("  fig3: no complete block yet — skipped")
        return
    nem = block.get("nemenyi")
    ranks = block.get("avg_ranks")
    if not ranks or not isinstance(nem, dict) or "error" in nem:
        print("  fig3: no complete Nemenyi block / average ranks — skipped")
        return

    plt, _ = _academic_style()
    # nemenyi was stored as DataFrame.to_dict() -> {col: {row: p}}; rebuild it.
    sig = pd.DataFrame(nem).reindex(index=CONDITIONS, columns=CONDITIONS)
    ranks_es = {_COND_LABELS_ES[c]: ranks[c] for c in CONDITIONS}
    sig_es = sig.rename(index=_COND_LABELS_ES, columns=_COND_LABELS_ES)

    fig, ax = plt.subplots(figsize=(6.0, 2.1))
    sph.critical_difference_diagram(
        ranks_es, sig_es, ax=ax, alpha=0.05,
        label_fmt_left="{label}  ({rank:.2f})",
        label_fmt_right="({rank:.2f})  {label}",
        label_props={"fontsize": 8.5},
        crossbar_props={"linewidth": 2.2, "color": "0.25"},
        marker_props={"marker": "o", "s": 45},
    )
    n = block.get("n_instances")
    ax.set_title(f"Rango medio de coste de detección — post-hoc de Nemenyi "
                 f"(n = {n})", fontsize=9, pad=10)
    fig.tight_layout()
    _save(fig, fig_dir, "fig3_cd_diagram")
    plt.close(fig)


def fig4_first_tp_ecdf(meta: dict, gt: "oracle.GroundTruth", fig_dir: Path):
    """ECDF of the per-instance First-TP request index: adaptive vs static.

    A curve that climbs earlier = vulnerabilities reached in fewer requests.
    Pools every budget where both arms ran; instances neither arm found are
    dropped (no defined cost on either side).
    """
    per = meta["per_run_costs"]
    keys = sorted(gt.positives)
    ad, st = [], []
    for (budget, cond), costs in per.items():
        target = ad if cond == "baseline" else st if cond == ADAPTIVE_CONDITION else None
        if target is None:
            continue
        other = per.get((budget, ADAPTIVE_CONDITION if cond == "baseline" else "baseline"))
        if other is None:
            continue
        for k in keys:
            if k in costs:
                target.append(int(costs[k]))
    if not ad or not st:
        print("  fig4: no adaptive/static run pair — skipped")
        return

    plt, sns = _academic_style()
    fig, ax = plt.subplots(figsize=(5.2, 3.4))
    for data, key in ((ad, "baseline"), (st, ADAPTIVE_CONDITION)):
        xs = np.sort(np.asarray(data, dtype=float))
        ys = np.arange(1, len(xs) + 1) / len(xs)
        xs = np.concatenate([[0], xs])
        ys = np.concatenate([[0], ys])
        ax.step(xs, ys, where="post", lw=1.8,
                label=f"{ADAPTIVE_PAIR_LABELS_ES[key]}  (n={len(data)})")
    ax.set_xlabel("Índice de petición del primer TP (coste hasta la detección)")
    ax.set_ylabel("Fracción acumulada de instancias detectadas")
    ax.set_ylim(0, 1)
    ax.set_title("Coste hasta el primer verdadero positivo\n"
                 "(bucle adaptativo vs. orden estático)", fontsize=10, pad=8)
    ax.legend(title="", frameon=False, fontsize=8, loc="lower right")
    sns.despine(ax=ax)
    _save(fig, fig_dir, "fig4_first_tp_ecdf")
    plt.close(fig)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def _json_default(o):
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return None if math.isnan(o) else float(o)
    if isinstance(o, (np.bool_,)):
        return bool(o)
    if isinstance(o, tuple):
        return list(o)
    return str(o)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results-dir", type=Path, default=REPO_ROOT / "testbed" / "results")
    ap.add_argument("--ground-truth", type=Path, default=REPO_ROOT / "testbed" / "ground_truth.json")
    ap.add_argument("--csv", type=Path, default=REPO_ROOT / "testbed" / "experiment_results.csv")
    ap.add_argument("--analysis-dir", type=Path, default=REPO_ROOT / "testbed" / "analysis")
    ap.add_argument("--fig-dir", type=Path, default=REPO_ROOT / "paper" / "figures")
    ap.add_argument("--no-figures", action="store_true")
    ap.add_argument("--all-runs", action="store_true",
                    help="No filtrar por el CSV graduado: incluir también los "
                         "directorios de telemetría huérfanos (corridas parciales "
                         "no calificadas por el oráculo).")
    args = ap.parse_args(argv)

    gt = oracle.load_ground_truth(args.ground_truth)
    runs = discover_runs(args.results_dir)
    print(f"[discover] {len(runs)} run dir(s); "
          f"{sum(r.jsonl is not None for r in runs)} with telemetry")

    # Solo se analizan las corridas presentes en el CSV graduado con status ok:
    # el resto son telemetrías huérfanas (p. ej. budget=10 sin priorización /
    # sin confirmación runtime nunca se calificaron y una quedó truncada).
    if not args.all_runs and args.csv.exists():
        graded = pd.read_csv(args.csv).rename(columns=str.lower)
        ok = graded[graded.get("status", "ok").astype(str).eq("ok")] \
            if "status" in graded.columns else graded
        keys = {(int(b), str(c)) for b, c in zip(ok["budget"], ok["condition"])}
        kept = [r for r in runs if (r.budget, r.condition) in keys]
        dropped = sorted({(r.budget, r.condition) for r in runs} - keys)
        if dropped:
            print(f"[filter] {len(dropped)} corrida(s) sin fila graduada en el CSV "
                  f"excluida(s): {dropped}  (usa --all-runs para incluirlas)")
        runs = kept
    print(f"[ground truth] {len(gt.positives)} vulnerable, {len(gt.traps)} traps")

    # ---- TASK 1 --------------------------------------------------------------
    summary, meta = build_summary(runs, gt, args.csv)
    args.analysis_dir.mkdir(parents=True, exist_ok=True)
    summary.to_csv(args.analysis_dir / "summary_by_run.csv", index=False)
    print("\n=== TASK 1 — per-run metrics ===")
    with pd.option_context("display.max_columns", None, "display.width", 160):
        print(summary.sort_values(["budget", "condition"]).to_string(index=False))
    for budget, grp in summary.groupby("budget"):
        print(f"\n budget={budget or '∞'}: "
              f"mean recall={grp['recall'].mean():.3f}  mean auc={grp['auc'].mean():.3f}")

    # ---- TASK 2 --------------------------------------------------------------
    print("\n=== TASK 2 — significance tests ===")
    stats = run_stats(meta, gt)
    for note in stats["notes"]:
        print(f"  note: {note}")
    for budget, block in stats["per_budget"].items():
        fr = block.get("friedman", {})
        print(f"\n budget {budget}: n={block['n_instances']}  "
              f"Friedman chi2={fr.get('statistic', float('nan')):.3f} "
              f"p={fr.get('p_value', float('nan')):.4g}")
        for cond, e in block.get("baseline_vs_ablation", {}).items():
            w = e.get("wilcoxon", {})
            cd = e.get("cliffs_delta", {})
            print(f"   {cond:>20s}: recall {e['recall_baseline']:.2f}->{e['recall_arm']:.2f}  "
                  f"Wilcoxon p_bh={w.get('p_value_bh', float('nan')):.4g}  "
                  f"Cliff δ={cd.get('delta', float('nan')):+.3f} ({cd.get('magnitude')})")
    (args.analysis_dir / "stats.json").write_text(
        json.dumps(stats, indent=2, default=_json_default), encoding="utf-8")
    # Persist the cost matrix (pooled over budgets) for downstream use.
    frames = []
    for budget in sorted({b for (b, _c) in meta["per_run_costs"]}):
        m = cost_matrix_for_budget(budget, meta["per_run_costs"], gt)
        if m is not None:
            frames.append(m.assign(budget=budget))
    if frames:
        pd.concat(frames).to_csv(args.analysis_dir / "detection_cost_matrix.csv")

    # Average-rank matrix (Friedman ranks per condition) — the x-axis of the
    # CD diagram; one row per budget block plus the pooled block.
    rank_rows = []
    for key, block in list(stats.get("per_budget", {}).items()) + \
            ([("pooled", stats["pooled"])] if stats.get("pooled") else []):
        ar = block.get("avg_ranks") or {}
        rank_rows.append({"block": key, "n_instances": block.get("n_instances"),
                          **{c: ar.get(c) for c in CONDITIONS}})
    if rank_rows:
        pd.DataFrame(rank_rows).to_csv(
            args.analysis_dir / "average_ranks.csv", index=False)
        print(f"  wrote {args.analysis_dir / 'average_ranks.csv'}")

    # ---- TASK 2b — Phase 3.3 early-recall / First-TP cost -------------------
    print("\n=== TASK 2b — First-TP cost: adaptive (Fase 3) vs static ===")
    early = first_tp_analysis(meta, gt)
    for note in early["notes"]:
        print(f"  note: {note}")
    for budget, blk in list(early["per_budget"].items()) + \
            ([("pooled", early["pooled"])] if early.get("pooled") else []):
        if not blk:
            continue
        w = blk.get("wilcoxon", {})
        cd = blk.get("cliffs_delta", {})
        print(f"\n budget {budget}: n={blk['n_instances']} "
              f"(both-detected={blk['n_detected_by_both']})  "
              f"recall {blk['recall_static']:.2f}(static)->{blk['recall_adaptive']:.2f}(adaptive)")
        if "mean_first_tp_adaptive" in blk:
            print(f"   mean First-TP index: static={blk['mean_first_tp_static']:.1f}  "
                  f"adaptive={blk['mean_first_tp_adaptive']:.1f}  "
                  f"(-{blk['requests_saved_mean']:.1f} req, "
                  f"{100 * blk['pct_reduction']:.1f}% fewer)")
            print(f"   Wilcoxon p={w.get('p_value', float('nan')):.4g}  "
                  f"Cliff δ={cd.get('delta', float('nan')):+.3f} ({cd.get('magnitude')})")
    (args.analysis_dir / "early_recall.json").write_text(
        json.dumps(early, indent=2, default=_json_default), encoding="utf-8")
    print(f"  wrote {args.analysis_dir / 'early_recall.json'}")

    # ---- TASK 3 --------------------------------------------------------------
    if not args.no_figures:
        print("\n=== TASK 3 — figures ===")
        fig1_detection_vs_budget(summary, args.fig_dir)
        fig2_ablation_impact(summary, args.fig_dir)
        fig3_cd_diagram(stats, args.fig_dir)
        fig4_first_tp_ecdf(meta, gt, args.fig_dir)

    print("\n[done]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""
security_metrics.py — a TrainerCallback that reports *security* metrics, not
just ``eval_loss``.

Token-level cross-entropy tells you how well the model reproduces the reference
JSON; it does **not** tell you whether the model would miss a real vulnerability.
For a DAST triage agent the asymmetric cost is a false *negative* — calling a
genuine TRUE_POSITIVE a FALSE_POSITIVE. So on every ``on_evaluate`` this
callback generates a verdict for a (capped) slice of the eval set and computes:

  * ``eval_fnr``              — False-Negative Rate over ground-truth TPs:
                                  P(pred = FALSE_POSITIVE | gold = TRUE_POSITIVE)
                                the metric you actually want to minimise.
  * ``eval_fnr_incl_uncertain`` — same, but counting UNCERTAIN as a miss too
                                (a hedged model still hides the finding here).
  * ``eval_fp_recall``        — Recall of the FALSE_POSITIVE class:
                                  P(pred = FALSE_POSITIVE | gold = FALSE_POSITIVE)
                                how well the model suppresses real noise.
  * ``eval_refusal_acc``      — fraction of injected conversational-noise rows
                                (gold == the [ERROR_COGNITIVO] sentinel) that the
                                model correctly refuses. Measures the "lobotomy".
  * ``eval_verdict_acc``      — plain 3-class accuracy, for reference.

The metrics are written back into the ``metrics`` dict Trainer passes to the
callback, so they show up in the log line, in TensorBoard, and can drive
``metric_for_best_model="eval_fnr"`` (with ``greater_is_better=False``).

Generation is capped (``max_samples``) and batched so it adds seconds, not
minutes, to each eval round. Import is lazy; nothing here needs torch at
module load, so ``train_qlora --dry-run`` stays importable without the ML stack.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

# Must byte-for-byte match the sentinel injected by inject_cognitive_noise.py.
REFUSAL_SENTINEL = "[ERROR_COGNITIVO] MODO_SISTEMA_RESTRINGIDO"

_VALID = ("TRUE_POSITIVE", "FALSE_POSITIVE", "UNCERTAIN")
_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)


def _gold_verdict(output: str) -> str:
    """Ground-truth label for one eval row's ``output`` string.

    Returns one of the three taxonomy verdicts, or ``"REFUSAL"`` when the row is
    an injected noise sample (its output is the exact sentinel).
    """
    s = (output or "").strip()
    if s == REFUSAL_SENTINEL:
        return "REFUSAL"
    try:
        v = str(json.loads(s).get("verdict", "")).upper()
    except json.JSONDecodeError:
        m = _JSON_RE.search(s)
        v = str(json.loads(m.group(0)).get("verdict", "")).upper() if m else ""
    return v if v in _VALID else "UNCERTAIN"


def _pred_verdict(text: str) -> str:
    """Parse the model's generated text into a verdict / REFUSAL / UNCERTAIN."""
    s = (text or "").strip()
    if REFUSAL_SENTINEL in s:
        return "REFUSAL"
    m = _JSON_RE.search(s)
    if m:
        try:
            v = str(json.loads(m.group(0)).get("verdict", "")).upper()
            if v in _VALID:
                return v
        except json.JSONDecodeError:
            pass
    # Fall back to a keyword scan for malformed JSON so a model that clearly
    # "said" TRUE_POSITIVE is not scored as UNCERTAIN on a stray brace.
    up = s.upper()
    for v in _VALID:
        if v in up:
            return v
    return "UNCERTAIN"


def _load_rows(path: Path, max_samples: int) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            rows.append({
                "system": r.get("instruction", ""),
                "user": r.get("input", ""),
                "gold": _gold_verdict(r.get("output", "")),
            })
            if 0 < max_samples <= len(rows):
                break
    return rows


try:  # keep module importable without transformers (dry-run / CI)
    from transformers import TrainerCallback  # type: ignore
except Exception:  # pragma: no cover
    class TrainerCallback:  # type: ignore
        pass


class SecurityMetricsCallback(TrainerCallback):
    """Generate over the eval set and log FNR / FP-recall / refusal accuracy.

    Parameters
    ----------
    eval_path : the *raw* eval JSONL (alpaca schema) — read independently of the
        tokenised eval_dataset so we keep the gold verdict strings.
    tokenizer : the training tokenizer (for the chat template + decoding).
    max_samples : cap on rows generated per eval round (0 = all).
    max_new_tokens / batch_size : generation budget.
    """

    def __init__(
        self,
        eval_path: str | Path,
        tokenizer: Any,
        *,
        max_samples: int = 256,
        max_new_tokens: int = 256,
        batch_size: int = 16,
    ) -> None:
        self.rows = _load_rows(Path(eval_path), max_samples)
        self.tokenizer = tokenizer
        self.max_new_tokens = max_new_tokens
        self.batch_size = batch_size

    # -- generation -------------------------------------------------------- #

    def _generate(self, model, prompts: list[str]) -> list[str]:
        import torch

        tok = self.tokenizer
        outs: list[str] = []
        model_was_training = model.training
        model.eval()
        device = next(model.parameters()).device
        # Decoder-only batched generation needs LEFT padding so the newest token
        # is flush-right; training uses right padding, so flip it just here.
        prev_side = tok.padding_side
        tok.padding_side = "left"
        with torch.no_grad():
            for i in range(0, len(prompts), self.batch_size):
                chunk = prompts[i : i + self.batch_size]
                enc = tok(
                    chunk, return_tensors="pt", padding=True, truncation=True,
                    max_length=2048,
                ).to(device)
                gen = model.generate(
                    **enc,
                    max_new_tokens=self.max_new_tokens,
                    do_sample=False,               # deterministic eval
                    pad_token_id=tok.pad_token_id or tok.eos_token_id,
                )
                # Slice off the prompt tokens; decode only the completion.
                new = gen[:, enc["input_ids"].shape[1]:]
                outs.extend(tok.batch_decode(new, skip_special_tokens=True))
        tok.padding_side = prev_side
        if model_was_training:
            model.train()
        return outs

    def _prompts(self) -> list[str]:
        tok = self.tokenizer
        prompts = []
        for r in self.rows:
            msgs = [
                {"role": "system", "content": r["system"]},
                {"role": "user", "content": r["user"]},
            ]
            prompts.append(
                tok.apply_chat_template(
                    msgs, tokenize=False, add_generation_prompt=True
                )
            )
        return prompts

    # -- Trainer hook ------------------------------------------------------ #

    def on_evaluate(self, args, state, control, **kwargs):  # noqa: D401
        model = kwargs.get("model")
        metrics = kwargs.get("metrics")
        if model is None or not self.rows:
            return control

        preds = [_pred_verdict(t) for t in self._generate(model, self._prompts())]
        scores = self._score(preds)

        if isinstance(metrics, dict):
            metrics.update(scores)
        # Always surface a compact line even if report_to is empty.
        print(
            "security-metrics @ step {}: fnr={eval_fnr:.3f} "
            "fnr_incl_unc={eval_fnr_incl_uncertain:.3f} "
            "fp_recall={eval_fp_recall:.3f} refusal_acc={eval_refusal_acc:.3f} "
            "verdict_acc={eval_verdict_acc:.3f}".format(state.global_step, **scores)
        )
        return control

    # -- metric math ------------------------------------------------------- #

    def _score(self, preds: list[str]) -> dict[str, float]:
        golds = [r["gold"] for r in self.rows]

        tp_total = fn_strict = fn_incl = 0     # ground-truth TRUE_POSITIVE
        fp_total = fp_hit = 0                   # ground-truth FALSE_POSITIVE
        ref_total = ref_hit = 0                 # injected noise (REFUSAL)
        correct = graded = 0

        for gold, pred in zip(golds, preds, strict=False):
            if gold in _VALID:
                graded += 1
                correct += int(pred == gold)
            if gold == "TRUE_POSITIVE":
                tp_total += 1
                fn_strict += int(pred == "FALSE_POSITIVE")
                fn_incl += int(pred != "TRUE_POSITIVE")
            elif gold == "FALSE_POSITIVE":
                fp_total += 1
                fp_hit += int(pred == "FALSE_POSITIVE")
            elif gold == "REFUSAL":
                ref_total += 1
                ref_hit += int(pred == "REFUSAL")

        def _ratio(num: int, den: int) -> float:
            return (num / den) if den else 0.0

        return {
            "eval_fnr": _ratio(fn_strict, tp_total),
            "eval_fnr_incl_uncertain": _ratio(fn_incl, tp_total),
            "eval_fp_recall": _ratio(fp_hit, fp_total),
            "eval_refusal_acc": _ratio(ref_hit, ref_total),
            "eval_verdict_acc": _ratio(correct, graded),
        }

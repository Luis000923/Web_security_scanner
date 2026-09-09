#!/usr/bin/env python3
"""Pick a QLoRA base model that fits the GPU this machine actually has.

The pipeline is developed on a 6 GB RTX 4050 laptop and run on a 32 GB RTX 5090
workstation. A single hard-coded base model cannot serve both: the 7B that is
comfortable on the 5090 OOMs on the 4050, and a model small enough for the 4050
wastes most of the 5090. This module probes the VRAM at run time and maps it
onto a tier table.

    $ uv run python -m ai_module.auto_select_model
    unsloth/Qwen2.5-14B-Instruct-bnb-4bit

Stdout contract
---------------
In the default ``--format name`` mode stdout carries the model id and nothing
else, so a shell can capture it directly::

    BASE_MODEL="$(uv run python -m ai_module.auto_select_model)"

Every diagnostic goes to stderr. ``--format tsv`` and ``--format json`` emit the
full profile (VRAM, tier, device) for callers that want to report it, which is
how ``run_pipeline.sh`` builds its hardware-profiling line.

Degradation
-----------
This module never raises and never exits non-zero for an environment problem:
a missing torch, a CPU-only box or a broken driver all fall back to the CPU tier
(a 0.5B model that trains anywhere) with a warning on stderr. The pipeline runs
it *after* ``verify_uv_env.sh`` has installed the ML stack, so hitting that
fallback there means something is wrong — ``run_pipeline.sh`` says so loudly
rather than silently fine-tuning a toy model.

Exit codes:
    0  a model was selected (including via the degraded CPU fallback)
    2  bad usage
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, asdict
from typing import Optional

BYTES_PER_GIB = 1024 ** 3

# Tier table: (upper bound in GiB *inclusive*, env override, model id, note).
# The first tier whose bound the measured VRAM does not exceed wins, so the
# order matters and the last entry must be unbounded.
#
# Sizes are 4-bit (bnb) checkpoints — the number that matters for QLoRA is the
# quantised weights plus optimiser/activation headroom, not the fp16 size.
TIER_TABLE = (
    (7.0,   "AUTO_MODEL_TIER1", "unsloth/Qwen2.5-1.5B-Instruct-bnb-4bit",
     "<=7 GB — laptop GPUs such as the RTX 4050 (6 GB)"),
    (16.0,  "AUTO_MODEL_TIER2", "unsloth/Qwen2.5-7B-Instruct-bnb-4bit",
     ">7 and <=16 GB — RTX 3080/4070/4080 class"),
    (None,  "AUTO_MODEL_TIER3", "unsloth/Qwen2.5-14B-Instruct-bnb-4bit",
     ">16 GB — RTX 5090 / A100 class"),
)

# Used when there is no usable CUDA device at all: small enough to fine-tune on
# CPU in a test, so an import-only CI run still exercises the whole pipeline.
CPU_FALLBACK_ENV = "AUTO_MODEL_TIER0"
CPU_FALLBACK_MODEL = "unsloth/Qwen2.5-0.5B-Instruct-bnb-4bit"

# Probe outcomes, in stable strings the shell can branch on.
STATUS_CUDA = "cuda"
STATUS_NO_TORCH = "no-torch"
STATUS_NO_CUDA = "no-cuda"
STATUS_PROBE_FAILED = "probe-failed"


@dataclass(frozen=True)
class Selection:
    """The full profiling result — what we saw and what we chose."""

    model: str
    tier: int                 # 0 = CPU fallback, 1..3 = GPU tiers
    vram_gb: float            # 0.0 when there is no GPU
    status: str
    device: str
    device_count: int
    detail: str

    @property
    def degraded(self) -> bool:
        return self.tier == 0


def _env_override(var: str, default: str) -> str:
    """Allow a site to re-point one tier without editing this table."""
    value = os.environ.get(var, "").strip()
    return value or default


def probe_vram(device: int = 0) -> tuple[Optional[float], str, str, int]:
    """Return ``(vram_gib, status, device_name, device_count)``.

    ``vram_gib`` is ``None`` whenever no usable CUDA device was found, in which
    case ``status`` says why. Importing torch is deferred to here so this module
    stays importable (and testable) without the ML stack installed.
    """
    try:
        import torch
    except Exception as exc:                      # ImportError, but also broken
        return None, STATUS_NO_TORCH, f"torch unavailable ({exc.__class__.__name__})", 0

    try:
        if not torch.cuda.is_available():
            return None, STATUS_NO_CUDA, "no CUDA device visible to torch", 0

        count = torch.cuda.device_count()
        if device >= count:
            return None, STATUS_NO_CUDA, f"device {device} requested but only {count} present", count

        props = torch.cuda.get_device_properties(device)
        return props.total_memory / BYTES_PER_GIB, STATUS_CUDA, props.name, count
    except Exception as exc:
        # A driver/runtime mismatch raises from inside torch.cuda rather than at
        # import; treat it exactly like "no GPU" instead of taking the run down.
        return None, STATUS_PROBE_FAILED, f"{exc.__class__.__name__}: {exc}", 0


def select_for_vram(vram_gb: Optional[float]) -> tuple[str, int]:
    """Map VRAM in GiB onto ``(model_id, tier)``. ``None`` -> CPU fallback."""
    if vram_gb is None:
        return _env_override(CPU_FALLBACK_ENV, CPU_FALLBACK_MODEL), 0

    for index, (upper, env_var, model, _note) in enumerate(TIER_TABLE, start=1):
        if upper is None or vram_gb <= upper:
            return _env_override(env_var, model), index

    raise AssertionError("TIER_TABLE must end with an unbounded tier")


def select(device: int = 0, simulated_vram_gb: Optional[float] = None) -> Selection:
    """Profile the hardware (or a simulated VRAM figure) and choose a model."""
    if simulated_vram_gb is not None:
        vram, status, name, count = simulated_vram_gb, STATUS_CUDA, "simulated", 1
        detail = f"simulated {simulated_vram_gb:.2f} GiB"
    else:
        vram, status, name, count = probe_vram(device)
        detail = name if status == STATUS_CUDA else name

    model, tier = select_for_vram(vram)
    return Selection(
        model=model,
        tier=tier,
        vram_gb=round(vram, 2) if vram is not None else 0.0,
        status=status,
        device=name if status == STATUS_CUDA else "cpu",
        device_count=count,
        detail=detail,
    )


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ai_module.auto_select_model",
        description="Select a QLoRA base model that fits the local GPU.",
    )
    parser.add_argument(
        "--format", choices=("name", "tsv", "json"), default="name",
        help="name (default): the model id alone, for shell capture. "
             "tsv: vram_gb<TAB>tier<TAB>model<TAB>device<TAB>status. json: full profile.",
    )
    parser.add_argument("--device", type=int, default=0, help="CUDA device index (default: 0)")
    parser.add_argument(
        "--simulate-vram-gb", type=float, default=None, metavar="GB",
        help="skip the probe and pretend the GPU has this much VRAM (testing)",
    )
    parser.add_argument("--quiet", action="store_true", help="suppress the stderr diagnostics")
    args = parser.parse_args(argv)

    if args.simulate_vram_gb is not None and args.simulate_vram_gb < 0:
        parser.error("--simulate-vram-gb must be >= 0")

    result = select(device=args.device, simulated_vram_gb=args.simulate_vram_gb)

    if not args.quiet:
        if result.degraded:
            print(
                f"[auto-select] no usable GPU ({result.status}: {result.detail}) — "
                f"falling back to {result.model}; install the ML stack with "
                f"'uv pip install -e \".[ai]\"' for a GPU-sized model",
                file=sys.stderr,
            )
        else:
            plural = f" (x{result.device_count})" if result.device_count > 1 else ""
            print(
                f"[auto-select] tier {result.tier}: {result.vram_gb:.1f} GiB VRAM on "
                f"{result.device}{plural} -> {result.model}",
                file=sys.stderr,
            )

    if args.format == "name":
        print(result.model)
    elif args.format == "tsv":
        print("\t".join((
            f"{result.vram_gb:.2f}", str(result.tier), result.model,
            result.device, result.status,
        )))
    else:
        print(json.dumps(asdict(result), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

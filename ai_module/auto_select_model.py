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

``--format recipe`` goes one step further and prints the *training knobs* that
fit the profiled device, as ``KEY=VALUE`` lines a shell can read without
``eval``::

    MODEL=unsloth/Qwen2.5-1.5B-Instruct-bnb-4bit
    LOAD_IN_4BIT=1
    PRECISION=fp16
    BATCH_SIZE=1
    GRAD_ACCUM=16
    MAX_SEQ_LEN=512
    ...

The model id alone is not enough on small or older GPUs: a 4 GB Turing card
(GTX 1650, sm_75) has no bf16 at all and no room for a native-precision base,
so it needs 4-bit weights, fp16 compute and a micro-batch — knobs that live
here, next to the VRAM probe that justifies them, rather than hard-coded in
``run_pipeline.sh``.

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
import platform
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

# bf16 needs Ampere (sm_80) or newer. Turing (sm_75: GTX 1650/1660, RTX 20xx)
# and Pascal report a CUDA device that torch happily allocates on, then abort
# inside TrainingArguments with "Your setup doesn't support bf16/gpu" — so the
# capability, not just the VRAM figure, has to reach the trainer.
BF16_MIN_CAPABILITY = (8, 0)
# TF32 is an Ampere tensor-core path; enabling it on older silicon is a no-op at
# best and a warning at worst.
TF32_MIN_CAPABILITY = (8, 0)

# Training knobs by VRAM ceiling, in the same "first tier that fits wins" order
# as TIER_TABLE. The last entry must be unbounded.
#
#   (upper GiB, 4-bit, batch, grad-accum, seq-len, lora_r, note)
#
# The effective token budget per optimiser step is batch * accum * seq, held
# roughly constant across tiers so the learning-rate schedule stays comparable:
# a 4 GB card gets there with 1x16x512 where a 32 GB card uses 8x2x2048.
RECIPE_TABLE = (
    (5.0,  True,  1, 16,  512, 16,
     "<=5 GB — GTX 1650 / MX class: 4-bit NF4, micro-batch, short sequences"),
    (7.0,  True,  2,  8,  768, 16,
     "<=7 GB — RTX 4050 laptop class: 4-bit NF4"),
    (12.0, True,  4,  4, 1024, 32,
     "<=12 GB — RTX 3060 12 GB class: 4-bit NF4"),
    (16.0, True,  4,  4, 1024, 32,
     "<=16 GB — RTX 4070/4080 class: 4-bit NF4"),
    (None, False, 8,  2, 2048, 32,
     ">16 GB — RTX 5090 / A100 class: native precision, no quantisation floor"),
)

# CPU has no VRAM ceiling to key off; it gets its own deliberately tiny recipe
# so an import-only CI run still exercises the whole pipeline in minutes.
CPU_RECIPE = (True, 1, 8, 512, 8, "no GPU — CPU fallback, tiny by design")


@dataclass(frozen=True)
class Recipe:
    """The training knobs that fit the profiled device.

    ``train_qlora.py`` owns the defaults; this is the per-machine override set
    that ``run_pipeline.sh`` forwards to it as CLI flags.
    """

    load_in_4bit: bool
    precision: str            # "bf16" | "fp16" | "fp32"
    batch_size: int
    grad_accum: int
    max_seq_len: int
    lora_r: int
    optim: str
    gradient_checkpointing: bool
    dataloader_num_workers: int
    attn_impl: str
    merge_adapter: bool
    tf32: bool
    note: str

    def as_env_lines(self) -> list[str]:
        """``KEY=VALUE`` lines for a shell to read without ``eval``."""
        def flag(value: bool) -> str:
            return "1" if value else "0"

        return [
            f"LOAD_IN_4BIT={flag(self.load_in_4bit)}",
            f"PRECISION={self.precision}",
            f"BATCH_SIZE={self.batch_size}",
            f"GRAD_ACCUM={self.grad_accum}",
            f"MAX_SEQ_LEN={self.max_seq_len}",
            f"LORA_R={self.lora_r}",
            f"OPTIM={self.optim}",
            f"GRADIENT_CHECKPOINTING={flag(self.gradient_checkpointing)}",
            f"NUM_WORKERS={self.dataloader_num_workers}",
            f"ATTN_IMPL={self.attn_impl}",
            f"MERGE_ADAPTER={flag(self.merge_adapter)}",
            f"TF32={flag(self.tf32)}",
        ]


def _default_num_workers() -> int:
    """0 on Windows.

    The DataLoader spawns (not forks) there, so every worker re-imports torch
    and re-pickles the dataset; on the small corpora this project trains on the
    spawn cost dominates, and persistent workers under MSYS/Git Bash regularly
    hang at the end of an epoch.
    """
    return 0 if platform.system() == "Windows" else 4


def build_recipe(
    vram_gb: Optional[float],
    capability: Optional[tuple[int, int]] = None,
) -> Recipe:
    """Map ``(VRAM, compute capability)`` onto a runnable set of knobs.

    ``vram_gb=None`` means "no usable GPU" and yields the CPU recipe.
    ``capability=None`` means the capability could not be read; we then assume
    the *conservative* answer (no bf16, no TF32), because guessing "yes" turns
    into a hard abort inside the trainer while guessing "no" only costs a
    little throughput on a card that would have supported it.
    """
    if vram_gb is None:
        four_bit, batch, accum, seq, lora_r, note = CPU_RECIPE
        precision = "fp32"          # fp16 on CPU is slower than fp32 and unstable
        tf32 = False
    else:
        chosen = None
        for row in RECIPE_TABLE:
            if row[0] is None or vram_gb <= row[0]:
                chosen = row
                break
        if chosen is None:  # pragma: no cover - RECIPE_TABLE ends unbounded
            raise AssertionError("RECIPE_TABLE must end with an unbounded tier")
        _upper, four_bit, batch, accum, seq, lora_r, note = chosen
        bf16_ok = capability is not None and capability >= BF16_MIN_CAPABILITY
        precision = "bf16" if bf16_ok else "fp16"
        tf32 = capability is not None and capability >= TF32_MIN_CAPABILITY

    return Recipe(
        load_in_4bit=four_bit,
        precision=precision,
        batch_size=batch,
        grad_accum=accum,
        max_seq_len=seq,
        lora_r=lora_r,
        # LoRA-only training keeps the optimiser state tiny, so the fused Torch
        # AdamW wins everywhere. Deliberately NOT paged_adamw_8bit: bitsandbytes
        # paged optimisers need CUDA unified memory, which Windows/WDDM does not
        # provide — exactly the machines that would want the memory saving.
        optim="adamw_torch_fused" if vram_gb is not None else "adamw_torch",
        gradient_checkpointing=True,
        dataloader_num_workers=_default_num_workers(),
        # FlashAttention-2 needs sm_80+ and its own wheel; SDPA is always there.
        attn_impl="sdpa",
        # peft cannot losslessly merge a LoRA back into 4-bit NF4 weights, so a
        # quantised run keeps the adapter separate and serves it on top.
        merge_adapter=not four_bit,
        tf32=tf32,
        note=note,
    )


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
    # Compute capability as "7.5" / "12.0", or "" when it could not be read.
    # This is what decides bf16 vs fp16, and it is independent of the VRAM
    # figure that decides the model size.
    capability: str = ""
    bf16_supported: bool = False
    recipe: Optional[Recipe] = None

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


def probe_capability(device: int = 0) -> Optional[tuple[int, int]]:
    """Return the CUDA compute capability as ``(major, minor)``, or ``None``.

    Kept separate from :func:`probe_vram` so its four-value contract (which
    ``run_pipeline.sh`` and the tests both depend on) stays untouched. Like the
    VRAM probe it never raises: an unreadable capability degrades to ``None``,
    which :func:`build_recipe` treats as "assume no bf16".
    """
    try:
        import torch

        if not torch.cuda.is_available():
            return None
        major, minor = torch.cuda.get_device_capability(device)
        return int(major), int(minor)
    except Exception:
        return None


def select_for_vram(vram_gb: Optional[float]) -> tuple[str, int]:
    """Map VRAM in GiB onto ``(model_id, tier)``. ``None`` -> CPU fallback."""
    if vram_gb is None:
        return _env_override(CPU_FALLBACK_ENV, CPU_FALLBACK_MODEL), 0

    for index, (upper, env_var, model, _note) in enumerate(TIER_TABLE, start=1):
        if upper is None or vram_gb <= upper:
            return _env_override(env_var, model), index

    raise AssertionError("TIER_TABLE must end with an unbounded tier")


def select(
    device: int = 0,
    simulated_vram_gb: Optional[float] = None,
    simulated_capability: Optional[tuple[int, int]] = None,
) -> Selection:
    """Profile the hardware (or a simulated GPU) and choose a model + recipe."""
    if simulated_vram_gb is not None:
        vram, status, name, count = simulated_vram_gb, STATUS_CUDA, "simulated", 1
        detail = f"simulated {simulated_vram_gb:.2f} GiB"
        capability = simulated_capability
    else:
        vram, status, name, count = probe_vram(device)
        detail = name if status == STATUS_CUDA else name
        capability = probe_capability(device) if status == STATUS_CUDA else None

    model, tier = select_for_vram(vram)
    recipe = build_recipe(vram, capability)
    return Selection(
        model=model,
        tier=tier,
        vram_gb=round(vram, 2) if vram is not None else 0.0,
        status=status,
        device=name if status == STATUS_CUDA else "cpu",
        device_count=count,
        detail=detail,
        capability=f"{capability[0]}.{capability[1]}" if capability else "",
        bf16_supported=bool(capability and capability >= BF16_MIN_CAPABILITY),
        recipe=recipe,
    )


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ai_module.auto_select_model",
        description="Select a QLoRA base model that fits the local GPU.",
    )
    parser.add_argument(
        "--format", choices=("name", "tsv", "json", "recipe"), default="name",
        help="name (default): the model id alone, for shell capture. "
             "tsv: vram_gb<TAB>tier<TAB>model<TAB>device<TAB>status. json: full profile. "
             "recipe: KEY=VALUE training knobs for the shell to forward to train_qlora.",
    )
    parser.add_argument("--device", type=int, default=0, help="CUDA device index (default: 0)")
    parser.add_argument(
        "--simulate-vram-gb", type=float, default=None, metavar="GB",
        help="skip the probe and pretend the GPU has this much VRAM (testing)",
    )
    parser.add_argument(
        "--simulate-capability", default=None, metavar="MAJOR.MINOR",
        help="pretend the GPU has this compute capability, e.g. 7.5 for Turing "
             "(testing; only meaningful with --simulate-vram-gb)",
    )
    parser.add_argument("--quiet", action="store_true", help="suppress the stderr diagnostics")
    args = parser.parse_args(argv)

    if args.simulate_vram_gb is not None and args.simulate_vram_gb < 0:
        parser.error("--simulate-vram-gb must be >= 0")

    simulated_capability = None
    if args.simulate_capability is not None:
        try:
            major, _, minor = args.simulate_capability.partition(".")
            simulated_capability = (int(major), int(minor or 0))
        except ValueError:
            parser.error("--simulate-capability must look like 7.5")

    result = select(
        device=args.device,
        simulated_vram_gb=args.simulate_vram_gb,
        simulated_capability=simulated_capability,
    )

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
            cap = f" sm_{result.capability.replace('.', '')}" if result.capability else ""
            print(
                f"[auto-select] tier {result.tier}: {result.vram_gb:.1f} GiB VRAM on "
                f"{result.device}{cap}{plural} -> {result.model}",
                file=sys.stderr,
            )
            if result.recipe and not result.bf16_supported and result.capability:
                print(
                    f"[auto-select] sm_{result.capability.replace('.', '')} has no bf16 — "
                    f"training in {result.recipe.precision}",
                    file=sys.stderr,
                )

    if args.format == "name":
        print(result.model)
    elif args.format == "tsv":
        print("\t".join((
            f"{result.vram_gb:.2f}", str(result.tier), result.model,
            result.device, result.status,
        )))
    elif args.format == "recipe":
        # MODEL first so a caller that only wants the id can read one line.
        print(f"MODEL={result.model}")
        print(f"TIER={result.tier}")
        print(f"VRAM_GB={result.vram_gb:.2f}")
        print(f"CAPABILITY={result.capability}")
        print(f"DEVICE={result.device}")
        print(f"STATUS={result.status}")
        for line in (result.recipe or build_recipe(None)).as_env_lines():
            print(line)
    else:
        print(json.dumps(asdict(result), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
train_qlora.py — QLoRA / Unsloth fine-tuning entrypoint.

Tuned for a single NVIDIA RTX 5090 (Blackwell, sm_120, 32 GB GDDR7):

  * 4-bit NF4 base weights (bitsandbytes) + bf16 LoRA adapters
  * Tensor-core friendly: bf16 compute, TF32 matmul, packed sequences
  * Attention: PyTorch SDPA by default (no extra wheels). FlashAttention-2 is
    strictly opt-in (``--flash-attn``) because ``flash-attn`` wheels for
    sm_120 / CUDA 12.8 are new and a missing wheel aborts the whole run.
  * Unsloth kernels are **opt-in** (``--use-unsloth``): its Triton kernels and
    pinned bitsandbytes often lag a brand-new GPU arch. The default path is
    plain ``transformers`` + ``peft`` + ``trl``; if Unsloth is requested but
    fails to import *or* fails to build its kernels at runtime
    (``RuntimeError`` / ``NotImplementedError``), we fall back automatically.

The heavy imports are done lazily inside `main()` so `--help` and unit tests
work without the ML stack installed.

TRL compatibility
-----------------
Training args are passed through ``trl.SFTConfig`` (not the bare
``transformers.TrainingArguments``); ``max_seq_length`` / ``packing`` /
``dataset_text_field`` live there. Because TRL renamed a few of these across
0.13 → 0.2x, every kwarg is filtered against the installed class signature
before construction, and the trainer takes ``processing_class`` (falling back
to ``tokenizer=`` only on older TRL).

Example
-------
    # full run
    python -m ai_module.train_qlora \
        --base-model unsloth/Qwen2.5-7B-Instruct-bnb-4bit \
        --dataset data/triage.train.jsonl \
        --eval  data/triage.val.jsonl \
        --output-dir runs/triage-qlora \
        --epochs 3 --batch-size 8 --grad-accum 2 --max-seq-len 2048

    # smoke test on arrival at the workstation (validates CUDA + bnb + adapters)
    python -m ai_module.train_qlora --dataset data/triage.train.jsonl \
        --output-dir runs/_smoke --max-steps 5

``--dry-run`` resolves and prints the config without importing the ML stack;
``--max-steps N`` runs a real but tiny optimisation loop and then exits.

Small-dataset defaults
----------------------
The synthetic triage corpus is ~800 examples of ~700 tokens, so the defaults
are tuned against overfitting rather than throughput: 3 epochs, 2048-token
sequences, ``lora_alpha = 2 * r`` with 5% LoRA dropout, per-epoch validation,
and ``load_best_model_at_end`` on ``eval_loss`` with an
``EarlyStoppingCallback`` (patience 2). Pass ``--eval FILE.jsonl`` to arm the
validation half — without it there is no metric to select on, so best-checkpoint
selection and early stopping stay off.
"""
from __future__ import annotations

import argparse
import inspect
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class TrainConfig:
    base_model: str = "unsloth/Qwen2.5-7B-Instruct-bnb-4bit"
    train: Path = Path("data/triage.train.jsonl")
    eval: Path | None = None
    output_dir: Path = Path("runs/qlora")
    # LoRA — standard recipe: alpha = 2 * r, small dropout for regularisation
    # on a small (~800 sample) synthetic corpus.
    lora_r: int = 32
    lora_alpha: int | None = None  # None -> 2 * lora_r (resolved in __post_init__)
    lora_dropout: float = 0.05
    target_modules: list[str] = field(default_factory=lambda: [
        "q_proj", "k_proj", "v_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj",
    ])
    # Optimisation
    epochs: float = 3.0
    batch_size: int = 8
    grad_accum: int = 2
    lr: float = 2e-4
    warmup_ratio: float = 0.03
    weight_decay: float = 0.01
    # Our triage/synthesis examples are ~700 tokens; 2048 leaves headroom while
    # cutting padding/attention cost versus the old 4096 default.
    max_seq_len: int = 2048
    max_steps: int = -1  # >0 overrides epochs (quick hardware/CUDA validation)
    # Validation / checkpoint selection (small-dataset overfit guard)
    save_total_limit: int = 2
    early_stopping_patience: int = 2
    early_stopping_threshold: float = 0.0
    # RTX 5090 knobs
    bf16: bool = True
    packing: bool = True
    gradient_checkpointing: bool = True
    # Blackwell / sm_120 safe defaults: SDPA attention, no Unsloth.
    attn_impl: str = "sdpa"           # "sdpa" | "flash_attention_2" | "eager"
    use_unsloth: bool = False
    merge_adapter: bool = False
    seed: int = 1337
    dataset_text_field: str = "text"

    def __post_init__(self) -> None:
        # Standard LoRA scaling: alpha = 2 * r unless explicitly overridden.
        if self.lora_alpha is None:
            self.lora_alpha = 2 * self.lora_r


# --------------------------------------------------------------------------- #
# kwarg filtering — tolerate TRL / transformers renames across versions
# --------------------------------------------------------------------------- #

def _supported_kwargs(target: Any, kwargs: dict[str, Any]) -> dict[str, Any]:
    """Keep only the kwargs ``target`` (a class / callable) actually accepts.

    If the signature exposes ``**kwargs`` we pass everything through. Used so a
    newer/older ``SFTConfig`` or ``SFTTrainer`` never blows up on a renamed or
    removed argument (``tokenizer`` -> ``processing_class``, ``max_seq_length``
    -> ``max_length`` ...).
    """
    try:
        sig = inspect.signature(target)
    except (TypeError, ValueError):
        return dict(kwargs)
    params = sig.parameters.values()
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params):
        return dict(kwargs)
    allowed = {p.name for p in params}
    return {k: v for k, v in kwargs.items() if k in allowed}


def _tune_cuda_for_blackwell() -> None:
    """Enable TF32 / flash-sdp and sane allocator behaviour for sm_120."""
    os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")
    try:
        import torch

        torch.backends.cuda.matmul.allow_tf32 = True
        torch.backends.cudnn.allow_tf32 = True
        if hasattr(torch.backends.cuda, "enable_flash_sdp"):
            torch.backends.cuda.enable_flash_sdp(True)
        if torch.cuda.is_available():
            cap = torch.cuda.get_device_capability()
            print(f"CUDA device: {torch.cuda.get_device_name(0)} (sm_{cap[0]}{cap[1]})")
    except Exception as exc:  # pragma: no cover
        print(f"warn: could not tune CUDA backend: {exc}")


def _tensorboard_available() -> bool:
    try:
        import tensorboard  # noqa: F401
    except Exception:
        return False
    return True


_ROLE = {"system": "system", "human": "user", "user": "user",
         "gpt": "assistant", "assistant": "assistant"}


def _row_to_messages(row: dict[str, Any]) -> list[dict[str, str]]:
    # Accept chatml ({"messages": [...]}), sharegpt ({"conversations": [...]})
    # and alpaca ({"instruction","input","output"}) schemas.
    if row.get("messages"):
        return list(row["messages"])
    if row.get("conversations"):
        return [
            {"role": _ROLE.get(t.get("from"), "user"), "content": t.get("value", "")}
            for t in row["conversations"]
        ]
    return [
        {"role": "system", "content": row.get("instruction", "")},
        {"role": "user", "content": row.get("input", "")},
        {"role": "assistant", "content": row.get("output", "")},
    ]


def _render_messages(messages: list[dict[str, str]], tokenizer: Any) -> str:
    """Render a conversation to a single training string.

    Uses the tokenizer's chat template when it has one; otherwise a plain
    ``ROLE: content`` join so a bare base-model tokenizer still trains.
    """
    tmpl = getattr(tokenizer, "chat_template", None)
    if tmpl:
        try:
            return tokenizer.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=False
            )
        except Exception:  # pragma: no cover - malformed template / roles
            pass
    return "\n".join(f"{m['role']}: {m['content']}" for m in messages)


def _load_dataset(path: Path, tokenizer: Any, text_field: str):
    from datasets import load_dataset

    ds = load_dataset("json", data_files=str(path), split="train")

    def _to_text(row):
        return {text_field: _render_messages(_row_to_messages(row), tokenizer)}

    return ds.map(_to_text, remove_columns=list(ds.column_names))


def _build_model_unsloth(cfg: TrainConfig):
    from unsloth import FastLanguageModel

    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=cfg.base_model,
        max_seq_length=cfg.max_seq_len,
        dtype=None,  # auto -> bf16 on Blackwell
        load_in_4bit=True,
    )
    model = FastLanguageModel.get_peft_model(
        model,
        r=cfg.lora_r,
        target_modules=cfg.target_modules,
        lora_alpha=cfg.lora_alpha,
        lora_dropout=cfg.lora_dropout,
        bias="none",
        use_gradient_checkpointing="unsloth" if cfg.gradient_checkpointing else False,
        random_state=cfg.seed,
    )
    return model, tokenizer


def _build_model_hf(cfg: TrainConfig):
    import torch
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

    bnb = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=torch.bfloat16,
        # Never silently spill the quantized model to CPU/disk: a partial
        # dispatch makes Accelerate raise "Some modules are dispatched on the
        # CPU or the disk" instead of OOMing loudly. QLoRA needs every base
        # weight resident on the GPU anyway.
        llm_int8_enable_fp32_cpu_offload=False,
    )

    # Pin the whole quantized model onto a single CUDA device. ``device_map=
    # "auto"`` lets Accelerate place layers on CPU/disk when its VRAM estimate
    # is conservative, which is exactly the failure we hit. Only fall back to
    # "auto" when there is no visible GPU (CPU smoke runs / CI).
    if torch.cuda.is_available():
        gpu_index = torch.cuda.current_device()
        device_map: Any = {"": gpu_index}
    else:
        device_map = "auto"
    tokenizer = AutoTokenizer.from_pretrained(cfg.base_model)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"  # required for training with bnb / SDPA / FA2
    model = AutoModelForCausalLM.from_pretrained(
        cfg.base_model,
        quantization_config=bnb,
        torch_dtype=torch.bfloat16,
        attn_implementation=cfg.attn_impl,
        device_map=device_map,
    )
    model = prepare_model_for_kbit_training(
        model, use_gradient_checkpointing=cfg.gradient_checkpointing
    )
    lora = LoraConfig(
        r=cfg.lora_r,
        lora_alpha=cfg.lora_alpha,
        lora_dropout=cfg.lora_dropout,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=cfg.target_modules,
    )
    return get_peft_model(model, lora), tokenizer


def _build_sft_config(cfg: TrainConfig, *, smoke: bool, have_eval: bool):
    """Construct ``trl.SFTConfig``, filtering renamed kwargs for the installed TRL."""
    from trl import SFTConfig

    report_to = []
    if not smoke and _tensorboard_available():
        report_to = ["tensorboard"]

    # Per-epoch validation is what makes early stopping / best-checkpoint
    # selection possible; without an eval set both are silently disabled
    # (``load_best_model_at_end`` requires eval_strategy == save_strategy).
    evaluate = have_eval and not smoke
    eval_strategy = "epoch" if evaluate else "no"
    save_strategy = "no" if smoke else "epoch"

    candidate: dict[str, Any] = dict(
        output_dir=str(cfg.output_dir),
        num_train_epochs=cfg.epochs,
        max_steps=cfg.max_steps if smoke else -1,
        per_device_train_batch_size=cfg.batch_size,
        per_device_eval_batch_size=cfg.batch_size,
        gradient_accumulation_steps=cfg.grad_accum,
        learning_rate=cfg.lr,
        warmup_ratio=0.0 if smoke else cfg.warmup_ratio,
        weight_decay=cfg.weight_decay,
        lr_scheduler_type="constant" if smoke else "cosine",
        bf16=cfg.bf16,
        tf32=True,
        logging_steps=1 if smoke else 10,
        save_strategy=save_strategy,
        save_total_limit=cfg.save_total_limit,
        # TRL/transformers renamed this in 4.46; pass both names and let
        # _supported_kwargs drop whichever the installed version lacks.
        eval_strategy=eval_strategy,
        evaluation_strategy=eval_strategy,
        load_best_model_at_end=evaluate,
        metric_for_best_model="eval_loss",
        greater_is_better=False,
        optim="paged_adamw_8bit",
        gradient_checkpointing=cfg.gradient_checkpointing,
        report_to=report_to,
        seed=cfg.seed,
        # --- SFT-specific (TRL) ---
        packing=cfg.packing,
        dataset_text_field=cfg.dataset_text_field,
        # TRL <0.20 calls this max_seq_length; newer calls it max_length. Pass
        # both keys and let _supported_kwargs drop whichever is absent.
        max_seq_length=cfg.max_seq_len,
        max_length=cfg.max_seq_len,
    )
    return SFTConfig(**_supported_kwargs(SFTConfig, candidate))


def _build_trainer(model, tokenizer, sft_config, train_ds, eval_ds, cfg=None):
    from trl import SFTTrainer

    candidate: dict[str, Any] = dict(
        model=model,
        args=sft_config,
        train_dataset=train_ds,
        eval_dataset=eval_ds,
        processing_class=tokenizer,  # TRL >= 0.16
        tokenizer=tokenizer,         # TRL < 0.16
    )
    allowed = _supported_kwargs(SFTTrainer.__init__, candidate)
    # Never pass both — prefer the modern name.
    if "processing_class" in allowed:
        allowed.pop("tokenizer", None)
    trainer = SFTTrainer(**allowed)
    _attach_early_stopping(trainer, cfg, have_eval=eval_ds is not None)
    return trainer


def _attach_early_stopping(trainer, cfg, *, have_eval: bool) -> None:
    """Stop training once eval_loss stops improving (small-dataset overfit guard).

    A no-op without an eval set (nothing to monitor) or when the patience is
    disabled with ``--early-stopping-patience 0``.
    """
    if cfg is None or not have_eval or cfg.early_stopping_patience <= 0:
        return
    if not getattr(trainer.args, "load_best_model_at_end", False):
        return
    from transformers import EarlyStoppingCallback

    trainer.add_callback(EarlyStoppingCallback(
        early_stopping_patience=cfg.early_stopping_patience,
        early_stopping_threshold=cfg.early_stopping_threshold,
    ))
    print(f"early stopping enabled: patience={cfg.early_stopping_patience} "
          f"eval rounds on eval_loss")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base-model", default=TrainConfig.base_model)
    ap.add_argument("--dataset", "--train", dest="dataset", type=Path, required=True,
                    metavar="FILE.jsonl",
                    help="training set from ai_module.dataset_generator "
                         "(alpaca / sharegpt / chatml — auto-detected)")
    ap.add_argument("--eval", type=Path, default=None)
    ap.add_argument("--output-dir", type=Path, default=TrainConfig.output_dir)
    ap.add_argument("--epochs", type=float, default=TrainConfig.epochs)
    ap.add_argument("--batch-size", type=int, default=TrainConfig.batch_size)
    ap.add_argument("--grad-accum", type=int, default=TrainConfig.grad_accum)
    ap.add_argument("--lr", type=float, default=TrainConfig.lr)
    ap.add_argument("--max-seq-len", type=int, default=TrainConfig.max_seq_len)
    ap.add_argument("--max-steps", type=int, default=TrainConfig.max_steps,
                    help="cap optimiser steps (>0 overrides --epochs); use "
                         "--max-steps 5 for a quick CUDA / bitsandbytes smoke test")
    ap.add_argument("--lora-r", type=int, default=TrainConfig.lora_r)
    ap.add_argument("--lora-alpha", type=int, default=None,
                    help="LoRA scaling (default: 2 * --lora-r)")
    ap.add_argument("--lora-dropout", type=float, default=TrainConfig.lora_dropout,
                    help="LoRA dropout; regularises small synthetic corpora")
    ap.add_argument("--save-total-limit", type=int, default=TrainConfig.save_total_limit,
                    help="checkpoints to keep on disk (best one is always kept)")
    ap.add_argument("--early-stopping-patience", type=int,
                    default=TrainConfig.early_stopping_patience,
                    help="stop after N evals without an eval_loss improvement "
                         "(0 disables; needs --eval)")
    ap.add_argument("--early-stopping-threshold", type=float,
                    default=TrainConfig.early_stopping_threshold,
                    help="minimum eval_loss delta that counts as an improvement")
    ap.add_argument("--use-unsloth", action="store_true",
                    help="opt in to Unsloth fused kernels (off by default on "
                         "Blackwell / sm_120; auto-falls back to transformers/peft "
                         "if the kernels fail to import or build)")
    ap.add_argument("--no-packing", action="store_true")
    ap.add_argument("--flash-attn", action="store_true",
                    help="use FlashAttention-2 instead of SDPA (needs a flash-attn "
                         "wheel built for your CUDA / GPU arch)")
    ap.add_argument("--merge-adapter", action="store_true",
                    help="also write a merged fp16 model next to the adapter "
                         "(ready to serve with vLLM / transformers)")
    ap.add_argument("--seed", type=int, default=TrainConfig.seed)
    ap.add_argument("--dry-run", action="store_true",
                    help="resolve + print config only; never imports torch")
    args = ap.parse_args(argv)

    cfg = TrainConfig(
        base_model=args.base_model,
        train=args.dataset,
        eval=args.eval,
        output_dir=args.output_dir,
        epochs=args.epochs,
        batch_size=args.batch_size,
        grad_accum=args.grad_accum,
        lr=args.lr,
        max_seq_len=args.max_seq_len,
        max_steps=args.max_steps,
        lora_r=args.lora_r,
        lora_alpha=args.lora_alpha,  # None -> 2 * lora_r
        lora_dropout=args.lora_dropout,
        save_total_limit=args.save_total_limit,
        early_stopping_patience=args.early_stopping_patience,
        early_stopping_threshold=args.early_stopping_threshold,
        packing=not args.no_packing,
        attn_impl="flash_attention_2" if args.flash_attn else "sdpa",
        use_unsloth=args.use_unsloth,
        merge_adapter=args.merge_adapter,
        seed=args.seed,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "train_config.json").write_text(
        json.dumps({k: str(v) for k, v in cfg.__dict__.items()}, indent=2)
    )
    print("resolved config:\n" + json.dumps({k: str(v) for k, v in cfg.__dict__.items()}, indent=2))
    if args.dry_run:
        return 0

    _tune_cuda_for_blackwell()

    build = _build_model_unsloth if cfg.use_unsloth else _build_model_hf
    try:
        model, tokenizer = build(cfg)
    except (ImportError, RuntimeError, NotImplementedError) as exc:
        if cfg.use_unsloth:
            print(f"unsloth path failed ({type(exc).__name__}: {exc}); "
                  f"falling back to transformers/peft")
            model, tokenizer = _build_model_hf(cfg)
        else:
            raise

    smoke = bool(cfg.max_steps and cfg.max_steps > 0)
    train_ds = _load_dataset(cfg.train, tokenizer, cfg.dataset_text_field)
    eval_ds = (
        _load_dataset(cfg.eval, tokenizer, cfg.dataset_text_field)
        if cfg.eval and not smoke else None
    )

    sft_config = _build_sft_config(cfg, smoke=smoke, have_eval=eval_ds is not None)
    trainer = _build_trainer(model, tokenizer, sft_config, train_ds, eval_ds, cfg)
    trainer.train()

    if smoke:
        print(f"smoke test OK — {cfg.max_steps} steps ran on "
              f"{_device_name()}; adapter not saved")
        return 0

    adapter_dir = cfg.output_dir / "adapter"
    trainer.save_model(str(adapter_dir))
    tokenizer.save_pretrained(str(adapter_dir))
    print(f"done -> {adapter_dir}")

    if cfg.merge_adapter:
        merged_dir = cfg.output_dir / "merged"
        try:
            merged = trainer.model.merge_and_unload()
            merged.save_pretrained(str(merged_dir), safe_serialization=True)
            tokenizer.save_pretrained(str(merged_dir))
            print(f"merged model -> {merged_dir}")
        except Exception as exc:  # pragma: no cover - best effort
            print(f"warn: merge_and_unload failed ({exc}); serve the adapter directly")
    return 0


def _device_name() -> str:
    try:
        import torch

        if torch.cuda.is_available():
            cap = torch.cuda.get_device_capability()
            return f"{torch.cuda.get_device_name(0)} (sm_{cap[0]}{cap[1]})"
    except Exception:
        pass
    return "CPU"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

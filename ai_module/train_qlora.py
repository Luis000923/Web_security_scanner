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
    # Native bf16 base. On a 32 GB RTX 5090 the 7B weights (~15 GB) + LoRA +
    # activations fit comfortably, so we drop the 4-bit NF4 path that was only
    # there to save VRAM. Use the *upstream* (non-prequantized) checkpoint —
    # the ``-bnb-4bit`` repo ships 4-bit weights and cannot be loaded in bf16.
    base_model: str = "Qwen/Qwen2.5-7B-Instruct"
    train: Path = Path("data/triage.train.jsonl")
    eval: Path | None = None
    output_dir: Path = Path("runs/qlora")
    # LoRA — standard recipe: alpha = 2 * r, small dropout for regularisation
    # on a small (~1.8k sample) synthetic corpus.
    lora_r: int = 32
    lora_alpha: int | None = None  # None -> 2 * lora_r (resolved in __post_init__)
    lora_dropout: float = 0.05
    target_modules: list[str] = field(default_factory=lambda: [
        "q_proj", "k_proj", "v_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj",
    ])
    # Optimisation — "cognitive lobotomy" recipe: enough epochs to overwrite the
    # general-assistant behaviour with the restricted security taxonomy, higher
    # weight decay to keep the adapter from memorising the small corpus verbatim.
    epochs: float = 6.0
    # RTX 5090 (32 GB) trains the full bf16 base with only LoRA params live, so a
    # real micro-batch of 16 fits and grad accumulation is unnecessary — dropping
    # it removes redundant book-keeping and improves SM occupancy.
    batch_size: int = 16
    grad_accum: int = 1
    lr: float = 1e-4
    warmup_ratio: float = 0.1
    weight_decay: float = 0.05
    # Our triage/synthesis examples are ~700 tokens; a 1024 ceiling leaves
    # headroom while roughly halving the padded attention cost versus 2048.
    max_seq_len: int = 1024
    max_steps: int = -1  # >0 overrides epochs (quick hardware/CUDA validation)
    # Validation / checkpoint selection (small-dataset overfit guard)
    save_total_limit: int = 2
    early_stopping_patience: int = 2
    early_stopping_threshold: float = 0.0
    # RTX 5090 knobs
    bf16: bool = True
    # 4-bit quantization is now OFF by default (native bf16). Kept as an opt-in
    # escape hatch (``--load-in-4bit``) for smaller GPUs / multi-model VRAM
    # sharing; it forces the bitsandbytes NF4 load path in _build_model_hf.
    load_in_4bit: bool = False
    # Packing OFF: each security sample is a strictly isolated sequence so the
    # loss for one finding never leaks cross-attention from an unrelated one.
    # This matters for the [ERROR_COGNITIVO] refusal examples especially.
    packing: bool = False
    gradient_checkpointing: bool = True
    # Blackwell / sm_120 safe defaults: SDPA attention, no Unsloth.
    attn_impl: str = "sdpa"           # "sdpa" | "flash_attention_2" | "eager"
    use_unsloth: bool = False
    merge_adapter: bool = False
    seed: int = 1337
    dataset_text_field: str = "text"
    # --- throughput / Blackwell kernel knobs ---
    # LoRA-only training => the AdamW state is tiny; the fused Torch kernel beats
    # paged_adamw_8bit (no CPU paging, no 8-bit de-quant per step).
    optim: str = "adamw_torch_fused"
    # Bucket batches by length so padding is to the batch max, not max_seq_len.
    group_by_length: bool = True
    # Pad the collated batch up to a multiple of 16 — Tensor-core friendly shapes.
    pad_to_multiple_of: int = 16
    dataloader_num_workers: int = 4
    # torch.compile is opt-in: warmup (~minutes) only pays off on long runs.
    torch_compile: bool = False

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
        torch.set_float32_matmul_precision("high")
        if hasattr(torch.backends.cuda, "enable_flash_sdp"):
            torch.backends.cuda.enable_flash_sdp(True)
        if hasattr(torch.backends.cuda, "enable_cudnn_sdp"):
            torch.backends.cuda.enable_cudnn_sdp(True)
        if hasattr(torch.backends.cuda, "enable_mem_efficient_sdp"):
            torch.backends.cuda.enable_mem_efficient_sdp(True)
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
        load_in_4bit=cfg.load_in_4bit,
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

    # Native bf16 by default; NF4 4-bit only when explicitly requested. The
    # 5090 has the VRAM for the full bf16 base, which trains faster and avoids
    # the quantization-error floor that caps LoRA quality.
    bnb = None
    if cfg.load_in_4bit:
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

    # Pin the whole model onto a single CUDA device. ``device_map="auto"`` lets
    # Accelerate place layers on CPU/disk when its VRAM estimate is
    # conservative, which is exactly the failure we hit. Only fall back to
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
        quantization_config=bnb,          # None -> full bf16 load
        torch_dtype=torch.bfloat16,
        attn_implementation=cfg.attn_impl,
        device_map=device_map,
    )
    if cfg.load_in_4bit:
        model = prepare_model_for_kbit_training(
            model, use_gradient_checkpointing=cfg.gradient_checkpointing
        )
    elif cfg.gradient_checkpointing:
        # kbit prep is what normally enables checkpointing + input grads; do it
        # by hand on the full-precision path so bf16 training still gets the
        # activation-memory savings.
        # Non-reentrant checkpointing: single forward, compatible with
        # torch.compile and forward hooks.
        model.gradient_checkpointing_enable(
            gradient_checkpointing_kwargs={"use_reentrant": False}
        )
        model.enable_input_require_grads()
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
        optim=cfg.optim,
        gradient_checkpointing=cfg.gradient_checkpointing,
        gradient_checkpointing_kwargs={"use_reentrant": False},
        report_to=report_to,
        seed=cfg.seed,
        # --- throughput: length bucketing, Tensor-core padding, DataLoader ---
        group_by_length=cfg.group_by_length and not cfg.packing,
        length_column_name="length",
        pad_to_multiple_of=cfg.pad_to_multiple_of,
        dataloader_num_workers=cfg.dataloader_num_workers,
        dataloader_pin_memory=True,
        dataloader_persistent_workers=cfg.dataloader_num_workers > 0,
        dataloader_prefetch_factor=4 if cfg.dataloader_num_workers > 0 else None,
        # --- graph compilation (opt-in) ---
        torch_compile=cfg.torch_compile,
        torch_compile_backend="inductor" if cfg.torch_compile else None,
        torch_compile_mode="default" if cfg.torch_compile else None,
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
    _attach_security_metrics(trainer, tokenizer, cfg, have_eval=eval_ds is not None)
    return trainer


def _attach_security_metrics(trainer, tokenizer, cfg, *, have_eval: bool) -> None:
    """Report FNR / FP-recall / refusal accuracy at each eval round.

    No-op without an eval set. Best-effort: a failure to build the callback
    (e.g. transformers too old) must never abort a training run.
    """
    if cfg is None or not have_eval or not cfg.eval:
        return
    try:
        from ai_module.security_metrics import SecurityMetricsCallback

        trainer.add_callback(SecurityMetricsCallback(cfg.eval, tokenizer))
        print("security metrics enabled: eval_fnr / eval_fp_recall / "
              "eval_refusal_acc reported each eval round")
    except Exception as exc:  # pragma: no cover - never fail the run for a metric
        print(f"warn: security-metrics callback disabled ({type(exc).__name__}: {exc})")


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
    ap.add_argument("--packing", action="store_true",
                    help="opt back into sequence packing (OFF by default: the "
                         "lobotomy recipe keeps every security sample isolated)")
    ap.add_argument("--no-packing", action="store_true",
                    help="explicit no-op; packing is already off by default")
    ap.add_argument("--load-in-4bit", action="store_true",
                    help="opt back into bitsandbytes NF4 4-bit base (OFF by "
                         "default; native bf16 fits on the 32 GB RTX 5090)")
    ap.add_argument("--flash-attn", action="store_true",
                    help="use FlashAttention-2 instead of SDPA (needs a flash-attn "
                         "wheel built for your CUDA / GPU arch)")
    ap.add_argument("--optim", default=TrainConfig.optim,
                    help="HF optimiser id (default: adamw_torch_fused — fastest "
                         "for LoRA-only training on a single GPU)")
    ap.add_argument("--num-workers", type=int, default=TrainConfig.dataloader_num_workers,
                    dest="num_workers", help="DataLoader worker processes")
    ap.add_argument("--pad-to-multiple-of", type=int,
                    default=TrainConfig.pad_to_multiple_of,
                    help="pad collated batches to a multiple of N (Tensor-core shapes)")
    ap.add_argument("--no-group-by-length", action="store_true",
                    help="disable length bucketing (padding then goes to max_seq_len)")
    ap.add_argument("--compile", dest="torch_compile", action="store_true",
                    help="torch.compile the model via inductor (warmup ~minutes; "
                         "worth it only on long runs / larger datasets)")
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
        packing=args.packing and not args.no_packing,
        load_in_4bit=args.load_in_4bit,
        attn_impl="flash_attention_2" if args.flash_attn else "sdpa",
        use_unsloth=args.use_unsloth,
        merge_adapter=args.merge_adapter,
        seed=args.seed,
        optim=args.optim,
        group_by_length=not args.no_group_by_length,
        pad_to_multiple_of=args.pad_to_multiple_of,
        dataloader_num_workers=args.num_workers,
        torch_compile=args.torch_compile,
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

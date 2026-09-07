#!/usr/bin/env python3
"""
train_qlora.py — QLoRA / Unsloth fine-tuning entrypoint.

Tuned for a single NVIDIA RTX 5090 (Blackwell, sm_120, 32 GB GDDR7):

  * 4-bit NF4 base weights (bitsandbytes) + bf16 LoRA adapters
  * Tensor-core friendly: bf16 compute, TF32 matmul, packed sequences
  * Unsloth kernels when available (2x throughput, ~40% less VRAM); the code
    falls back to plain `transformers` + `peft` + `trl` otherwise.

The heavy imports are done lazily inside `main()` so `--help` and unit tests
work without the ML stack installed.

Example
-------
    # full run
    python -m ai_module.train_qlora \
        --base-model unsloth/Qwen2.5-7B-Instruct-bnb-4bit \
        --dataset data/triage.train.jsonl \
        --eval  data/triage.val.jsonl \
        --output-dir runs/triage-qlora \
        --epochs 2 --batch-size 8 --grad-accum 2 --max-seq-len 4096

    # smoke test on arrival at the workstation (validates CUDA + bnb + adapters)
    python -m ai_module.train_qlora --dataset data/triage.train.jsonl \
        --output-dir runs/_smoke --max-steps 5

``--dry-run`` resolves and prints the config without importing the ML stack;
``--max-steps N`` runs a real but tiny optimisation loop and then exits.
"""
from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TrainConfig:
    base_model: str = "unsloth/Qwen2.5-7B-Instruct-bnb-4bit"
    train: Path = Path("data/triage.train.jsonl")
    eval: Path | None = None
    output_dir: Path = Path("runs/qlora")
    # LoRA
    lora_r: int = 32
    lora_alpha: int = 32
    lora_dropout: float = 0.0
    target_modules: list[str] = field(default_factory=lambda: [
        "q_proj", "k_proj", "v_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj",
    ])
    # Optimisation
    epochs: float = 2.0
    batch_size: int = 8
    grad_accum: int = 2
    lr: float = 2e-4
    warmup_ratio: float = 0.03
    weight_decay: float = 0.01
    max_seq_len: int = 4096
    max_steps: int = -1  # >0 overrides epochs (quick hardware/CUDA validation)
    # RTX 5090 knobs
    bf16: bool = True
    packing: bool = True
    gradient_checkpointing: bool = True
    use_unsloth: bool = True
    merge_adapter: bool = False
    seed: int = 1337


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


def _load_dataset(path: Path):
    from datasets import load_dataset

    ds = load_dataset("json", data_files=str(path), split="train")

    _ROLE = {"system": "system", "human": "user", "user": "user",
             "gpt": "assistant", "assistant": "assistant"}

    def _to_text(row):
        # Accept chatml ({"messages": [...]}), sharegpt ({"conversations": [...]})
        # and alpaca ({"instruction","input","output"}) schemas.
        if row.get("messages"):
            return {"messages": row["messages"]}
        if row.get("conversations"):
            return {"messages": [
                {"role": _ROLE.get(t.get("from"), "user"), "content": t.get("value", "")}
                for t in row["conversations"]
            ]}
        return {"messages": [
            {"role": "system", "content": row.get("instruction", "")},
            {"role": "user", "content": row.get("input", "")},
            {"role": "assistant", "content": row.get("output", "")},
        ]}

    return ds.map(_to_text, remove_columns=[c for c in ds.column_names if c != "messages"])


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
    )
    tokenizer = AutoTokenizer.from_pretrained(cfg.base_model)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    model = AutoModelForCausalLM.from_pretrained(
        cfg.base_model,
        quantization_config=bnb,
        torch_dtype=torch.bfloat16,
        attn_implementation="flash_attention_2",
        device_map="auto",
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
    ap.add_argument("--lora-alpha", type=int, default=TrainConfig.lora_alpha)
    ap.add_argument("--no-unsloth", action="store_true", help="force transformers/peft path")
    ap.add_argument("--no-packing", action="store_true")
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
        lora_alpha=args.lora_alpha,
        packing=not args.no_packing,
        use_unsloth=not args.no_unsloth,
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

    from transformers import TrainingArguments
    from trl import SFTTrainer

    build = _build_model_unsloth if cfg.use_unsloth else _build_model_hf
    try:
        model, tokenizer = build(cfg)
    except ImportError as exc:
        if cfg.use_unsloth:
            print(f"unsloth unavailable ({exc}); falling back to transformers/peft")
            model, tokenizer = _build_model_hf(cfg)
        else:
            raise

    train_ds = _load_dataset(cfg.train)
    eval_ds = _load_dataset(cfg.eval) if cfg.eval else None

    smoke = cfg.max_steps and cfg.max_steps > 0
    targs = TrainingArguments(
        output_dir=str(cfg.output_dir),
        num_train_epochs=cfg.epochs,
        max_steps=cfg.max_steps if smoke else -1,
        per_device_train_batch_size=cfg.batch_size,
        gradient_accumulation_steps=cfg.grad_accum,
        learning_rate=cfg.lr,
        warmup_ratio=0.0 if smoke else cfg.warmup_ratio,
        weight_decay=cfg.weight_decay,
        lr_scheduler_type="constant" if smoke else "cosine",
        bf16=cfg.bf16,
        tf32=True,
        logging_steps=1 if smoke else 10,
        save_strategy="no" if smoke else "epoch",
        eval_strategy="epoch" if (eval_ds is not None and not smoke) else "no",
        optim="paged_adamw_8bit",
        gradient_checkpointing=cfg.gradient_checkpointing,
        report_to=[] if smoke else ["tensorboard"],
        seed=cfg.seed,
    )

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        args=targs,
        train_dataset=train_ds,
        eval_dataset=eval_ds,
        max_seq_length=cfg.max_seq_len,
        packing=cfg.packing,
    )
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

"""API smoke test for ai_module/train_qlora.py (AUDIT.md 3.1 / P0-1).

TRL >= 0.12 moved ``max_seq_length`` / ``packing`` / ``dataset_text_field``
from ``transformers.TrainingArguments`` onto ``trl.SFTConfig`` and renamed
``SFTTrainer(tokenizer=...)`` to ``processing_class=``. ``train_qlora.py``
already targets that surface (``_build_sft_config`` / ``_build_trainer``,
both filtering kwargs through ``_supported_kwargs`` so a rename on either
side degrades instead of crashing) -- this test's only job is to catch a
*regression*: a future TRL release renaming or removing something these
functions rely on, without needing a GPU, a real checkpoint, or any network
access.

It builds a tiny random GPT-2 (a few KB, CPU-only) and a from-scratch BPE
tokenizer entirely offline, then constructs ``SFTConfig`` + ``SFTTrainer``
through the module's own helpers and asserts they come back as real
instances -- exactly "instantiate the Trainer without training".
"""
from __future__ import annotations

from pathlib import Path

import pytest

torch = pytest.importorskip("torch")
transformers = pytest.importorskip("transformers")
trl = pytest.importorskip("trl")
datasets = pytest.importorskip("datasets")
tokenizers = pytest.importorskip("tokenizers")

from ai_module.train_qlora import TrainConfig, _build_sft_config, _build_trainer  # noqa: E402

_TEXTS = [
    "hello world this is a smoke test",
    "another short example sentence here",
    "sqli finding true positive confirmed",
    "xss finding false positive escaped",
]


def _tiny_model_and_tokenizer(tmp_path: Path):
    from tokenizers import ByteLevelBPETokenizer
    from transformers import GPT2Config, GPT2LMHeadModel, GPT2TokenizerFast

    bpe = ByteLevelBPETokenizer()
    bpe.train_from_iterator(
        _TEXTS, vocab_size=300, min_frequency=1,
        special_tokens=["<pad>", "<s>", "</s>", "<unk>"],
    )
    vocab_dir = tmp_path / "vocab"
    vocab_dir.mkdir()
    bpe.save_model(str(vocab_dir))
    tokenizer = GPT2TokenizerFast(
        vocab_file=str(vocab_dir / "vocab.json"),
        merges_file=str(vocab_dir / "merges.txt"),
    )
    tokenizer.pad_token = "<pad>"

    config = GPT2Config(
        vocab_size=max(tokenizer.vocab_size, 300),
        n_positions=64, n_ctx=64, n_embd=32, n_layer=2, n_head=2,
    )
    model = GPT2LMHeadModel(config)
    model.resize_token_embeddings(len(tokenizer.get_vocab()))
    return model, tokenizer


def test_sft_config_and_trainer_build_without_training(tmp_path):
    """Regression guard for AUDIT.md 3.1: catches a TRL release that renames
    or removes an argument ``_build_sft_config`` / ``_build_trainer`` pass,
    before it surfaces as a crash at the start of a real training run.
    """
    model, tokenizer = _tiny_model_and_tokenizer(tmp_path)
    dataset = datasets.Dataset.from_dict({"text": _TEXTS})

    cfg = TrainConfig(
        output_dir=tmp_path / "out",
        max_steps=1,
        dataloader_num_workers=0,
        group_by_length=False,
        max_seq_len=32,
    )

    sft_config = _build_sft_config(cfg, smoke=True, have_eval=False)
    assert isinstance(sft_config, trl.SFTConfig)

    trainer = _build_trainer(model, tokenizer, sft_config, dataset, None, cfg=cfg)
    assert isinstance(trainer, trl.SFTTrainer)
    # The renamed kwarg actually landed -- not silently dropped to nothing.
    assert trainer.processing_class is tokenizer

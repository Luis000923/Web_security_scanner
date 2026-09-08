"""Import-safe unit tests for ai_module.train_qlora (no ML stack required)."""
from __future__ import annotations

import inspect
import json

from ai_module import train_qlora as tq


def test_defaults_are_blackwell_safe():
    cfg = tq.TrainConfig()
    assert cfg.use_unsloth is False
    assert cfg.attn_impl == "sdpa"
    assert cfg.dataset_text_field == "text"


def test_dry_run_resolves_and_writes_config(tmp_path, capsys):
    out = tmp_path / "run"
    rc = tq.main(["--dataset", "data/x.jsonl", "--output-dir", str(out), "--dry-run"])
    assert rc == 0
    saved = json.loads((out / "train_config.json").read_text())
    assert saved["attn_impl"] == "sdpa"
    assert saved["use_unsloth"] == "False"


def test_flags_flip_opt_in_knobs(tmp_path):
    out = tmp_path / "run"
    tq.main([
        "--dataset", "d.jsonl", "--output-dir", str(out),
        "--use-unsloth", "--flash-attn", "--no-packing", "--dry-run",
    ])
    saved = json.loads((out / "train_config.json").read_text())
    assert saved["use_unsloth"] == "True"
    assert saved["attn_impl"] == "flash_attention_2"
    assert saved["packing"] == "False"


def test_supported_kwargs_filters_unknown_names():
    def target(a, b, c=1):
        return (a, b, c)

    got = tq._supported_kwargs(target, {"a": 1, "b": 2, "zzz": 3})
    assert got == {"a": 1, "b": 2}


def test_supported_kwargs_passes_all_when_varkw():
    def target(a, **kw):
        return a

    payload = {"a": 1, "anything": 2}
    assert tq._supported_kwargs(target, payload) == payload


def test_render_messages_without_chat_template():
    class _Tok:
        chat_template = None

    msgs = [{"role": "system", "content": "S"}, {"role": "user", "content": "U"}]
    assert tq._render_messages(msgs, _Tok()) == "system: S\nuser: U"


def test_row_to_messages_schema_autodetect():
    assert tq._row_to_messages({"messages": [{"role": "user", "content": "x"}]}) == [
        {"role": "user", "content": "x"}
    ]
    sharegpt = tq._row_to_messages({"conversations": [{"from": "gpt", "value": "y"}]})
    assert sharegpt == [{"role": "assistant", "content": "y"}]
    alpaca = tq._row_to_messages({"instruction": "i", "input": "in", "output": "o"})
    assert [m["role"] for m in alpaca] == ["system", "user", "assistant"]


def test_build_sft_config_is_guarded_by_signature_filter():
    # Can't build the real SFTConfig without TRL installed; assert the helper
    # that protects the call is wired to the right callable.
    src = inspect.getsource(tq._build_sft_config)
    assert "_supported_kwargs(SFTConfig" in src
    assert "processing_class" in inspect.getsource(tq._build_trainer)


# --------------------------------------------------------------------------- #
# P0-2: small-dataset hyperparameters + validation / early stopping
# --------------------------------------------------------------------------- #

def test_small_dataset_defaults():
    cfg = tq.TrainConfig()
    assert cfg.epochs == 3.0
    assert cfg.max_seq_len == 2048
    assert cfg.lora_dropout == 0.05
    assert cfg.save_total_limit == 2
    assert cfg.early_stopping_patience == 2


def test_lora_alpha_defaults_to_twice_r():
    assert tq.TrainConfig().lora_alpha == 2 * tq.TrainConfig().lora_r
    assert tq.TrainConfig(lora_r=16).lora_alpha == 32
    # explicit value wins
    assert tq.TrainConfig(lora_r=16, lora_alpha=8).lora_alpha == 8


def test_cli_lora_alpha_follows_r(tmp_path):
    out = tmp_path / "run"
    tq.main(["--dataset", "d.jsonl", "--output-dir", str(out),
             "--lora-r", "8", "--dry-run"])
    saved = json.loads((out / "train_config.json").read_text())
    assert saved["lora_alpha"] == "16"


def _fake_sft_config(monkeypatch):
    """Install a stub ``trl.SFTConfig`` that just records its kwargs."""
    import sys
    import types

    class _SFTConfig:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    mod = types.ModuleType("trl")
    mod.SFTConfig = _SFTConfig
    monkeypatch.setitem(sys.modules, "trl", mod)
    return _SFTConfig


def test_sft_config_enables_best_checkpoint_selection_with_eval(monkeypatch):
    _fake_sft_config(monkeypatch)
    args = tq._build_sft_config(tq.TrainConfig(), smoke=False, have_eval=True)
    assert args.eval_strategy == "epoch"
    assert args.evaluation_strategy == "epoch"
    assert args.save_strategy == "epoch"
    assert args.load_best_model_at_end is True
    assert args.metric_for_best_model == "eval_loss"
    assert args.greater_is_better is False
    assert args.save_total_limit == 2


def test_sft_config_disables_best_checkpoint_without_eval(monkeypatch):
    _fake_sft_config(monkeypatch)
    args = tq._build_sft_config(tq.TrainConfig(), smoke=False, have_eval=False)
    # load_best_model_at_end requires eval_strategy == save_strategy.
    assert args.eval_strategy == "no"
    assert args.load_best_model_at_end is False


def test_sft_config_smoke_run_skips_eval(monkeypatch):
    _fake_sft_config(monkeypatch)
    args = tq._build_sft_config(tq.TrainConfig(), smoke=True, have_eval=True)
    assert args.eval_strategy == "no"
    assert args.save_strategy == "no"
    assert args.load_best_model_at_end is False


class _FakeTrainer:
    def __init__(self, load_best: bool = True):
        self.args = type("A", (), {"load_best_model_at_end": load_best})()
        self.callbacks: list = []

    def add_callback(self, cb):
        self.callbacks.append(cb)


def _fake_early_stopping(monkeypatch):
    import sys
    import types

    class _EarlyStoppingCallback:
        def __init__(self, early_stopping_patience=1, early_stopping_threshold=0.0):
            self.early_stopping_patience = early_stopping_patience
            self.early_stopping_threshold = early_stopping_threshold

    mod = types.ModuleType("transformers")
    mod.EarlyStoppingCallback = _EarlyStoppingCallback
    monkeypatch.setitem(sys.modules, "transformers", mod)
    return _EarlyStoppingCallback


def test_early_stopping_attached_when_eval_present(monkeypatch):
    _fake_early_stopping(monkeypatch)
    trainer = _FakeTrainer()
    tq._attach_early_stopping(trainer, tq.TrainConfig(), have_eval=True)
    assert len(trainer.callbacks) == 1
    assert trainer.callbacks[0].early_stopping_patience == 2


def test_early_stopping_skipped_without_eval_or_patience(monkeypatch):
    _fake_early_stopping(monkeypatch)
    no_eval = _FakeTrainer()
    tq._attach_early_stopping(no_eval, tq.TrainConfig(), have_eval=False)
    assert no_eval.callbacks == []

    disabled = _FakeTrainer()
    tq._attach_early_stopping(
        disabled, tq.TrainConfig(early_stopping_patience=0), have_eval=True
    )
    assert disabled.callbacks == []

    # smoke runs turn off load_best_model_at_end -> nothing to monitor
    smoke = _FakeTrainer(load_best=False)
    tq._attach_early_stopping(smoke, tq.TrainConfig(), have_eval=True)
    assert smoke.callbacks == []

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

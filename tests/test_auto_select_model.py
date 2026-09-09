"""Unit tests for ai_module.auto_select_model (no GPU or ML stack required)."""
from __future__ import annotations

import builtins
import json

import pytest

from ai_module import auto_select_model as asm


# --- tier boundaries -------------------------------------------------------
# The boundaries are the whole point of the module: 7.0 and 16.0 GiB are
# inclusive upper bounds, so a 6 GB RTX 4050 lands in tier 1 and a 32 GB
# RTX 5090 in tier 3.
@pytest.mark.parametrize("vram_gb,expected_tier", [
    (0.0, 1),
    (5.65, 1),    # measured RTX 4050 Laptop
    (6.9, 1),
    (7.0, 1),     # inclusive
    (7.01, 2),
    (11.9, 2),
    (16.0, 2),    # inclusive
    (16.01, 3),
    (31.4, 3),    # measured RTX 5090
    (79.2, 3),
])
def test_tier_boundaries(vram_gb, expected_tier):
    model, tier = asm.select_for_vram(vram_gb)
    assert tier == expected_tier
    assert model == asm.TIER_TABLE[expected_tier - 1][2]


def test_no_cuda_falls_back_to_the_cpu_tier():
    model, tier = asm.select_for_vram(None)
    assert tier == 0
    assert model == asm.CPU_FALLBACK_MODEL


def test_tiers_are_ordered_and_terminated():
    bounds = [upper for upper, _env, _model, _note in asm.TIER_TABLE]
    assert bounds[-1] is None, "the last tier must be unbounded"
    finite = [b for b in bounds if b is not None]
    assert finite == sorted(finite)


def test_every_tier_is_env_overridable(monkeypatch):
    monkeypatch.setenv("AUTO_MODEL_TIER1", "acme/tiny")
    monkeypatch.setenv("AUTO_MODEL_TIER0", "acme/cpu")
    assert asm.select_for_vram(4.0)[0] == "acme/tiny"
    assert asm.select_for_vram(None)[0] == "acme/cpu"
    # a blank override is ignored rather than selecting an empty model id
    monkeypatch.setenv("AUTO_MODEL_TIER1", "   ")
    assert asm.select_for_vram(4.0)[0] == asm.TIER_TABLE[0][2]


# --- degradation -----------------------------------------------------------
def test_probe_survives_missing_torch(monkeypatch):
    real_import = builtins.__import__

    def no_torch(name, *args, **kwargs):
        if name == "torch":
            raise ImportError("No module named 'torch'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_torch)
    vram, status, _detail, count = asm.probe_vram()
    assert vram is None
    assert status == asm.STATUS_NO_TORCH
    assert count == 0


def test_probe_survives_a_broken_driver(monkeypatch):
    """A CUDA/driver mismatch raises from inside torch.cuda, not at import."""
    real_import = builtins.__import__

    class _BrokenCuda:
        @staticmethod
        def is_available():
            raise RuntimeError("CUDA driver version is insufficient")

    class _FakeTorch:
        cuda = _BrokenCuda

    def fake_import(name, *args, **kwargs):
        if name == "torch":
            return _FakeTorch
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    vram, status, detail, _count = asm.probe_vram()
    assert vram is None
    assert status == asm.STATUS_PROBE_FAILED
    assert "RuntimeError" in detail


# --- CLI contract ----------------------------------------------------------
def test_default_format_prints_only_the_model_id(capsys):
    rc = asm.main(["--simulate-vram-gb", "31.4", "--quiet"])
    assert rc == 0
    out = capsys.readouterr().out
    # run_pipeline.sh captures this verbatim: exactly one line, nothing else.
    assert out == "unsloth/Qwen2.5-14B-Instruct-bnb-4bit\n"


def test_diagnostics_go_to_stderr_not_stdout(capsys):
    asm.main(["--simulate-vram-gb", "4.0"])
    captured = capsys.readouterr()
    assert captured.out.strip() == "unsloth/Qwen2.5-1.5B-Instruct-bnb-4bit"
    assert "[auto-select]" in captured.err


def test_tsv_format_matches_what_the_shell_reads(capsys):
    asm.main(["--simulate-vram-gb", "12.0", "--quiet", "--format", "tsv"])
    fields = capsys.readouterr().out.rstrip("\n").split("\t")
    # run_pipeline.sh: read -r AUTO_VRAM AUTO_TIER BASE_MODEL AUTO_DEVICE AUTO_STATUS
    assert len(fields) == 5
    vram, tier, model, _device, status = fields
    assert float(vram) == 12.0
    assert tier == "2"
    assert model == "unsloth/Qwen2.5-7B-Instruct-bnb-4bit"
    assert status == asm.STATUS_CUDA


def test_json_format_is_parseable(capsys):
    asm.main(["--simulate-vram-gb", "31.4", "--quiet", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["tier"] == 3
    assert payload["vram_gb"] == 31.4
    assert payload["model"].endswith("14B-Instruct-bnb-4bit")


def test_negative_simulated_vram_is_rejected():
    with pytest.raises(SystemExit) as exc:
        asm.main(["--simulate-vram-gb", "-1"])
    assert exc.value.code == 2

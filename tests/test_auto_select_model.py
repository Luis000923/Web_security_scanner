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


# --- training recipe -------------------------------------------------------
# The recipe is what makes a 4 GB Turing card usable: the model id alone says
# nothing about precision, quantisation or batch size, and getting any of those
# wrong on that card is a hard abort rather than a slow run.

@pytest.mark.parametrize("vram_gb,four_bit,batch,accum,seq", [
    (4.0,  True,  1, 16, 512),    # GTX 1650
    (5.0,  True,  1, 16, 512),    # inclusive
    (5.65, True,  2, 8,  768),    # measured RTX 4050
    (7.0,  True,  2, 8,  768),    # inclusive
    (12.0, True,  4, 4,  1024),
    (16.0, True,  4, 4,  1024),   # inclusive
    (31.4, False, 8, 2,  2048),   # measured RTX 5090
])
def test_recipe_scales_with_vram(vram_gb, four_bit, batch, accum, seq):
    recipe = asm.build_recipe(vram_gb, (8, 6))
    assert recipe.load_in_4bit is four_bit
    assert (recipe.batch_size, recipe.grad_accum, recipe.max_seq_len) == (batch, accum, seq)


def test_recipe_reproduces_the_workstation_knobs():
    """The >16 GB tier must keep the values run_pipeline.sh used to hard-code.

    Anything else would silently change the workstation runs the paper's
    numbers came from.
    """
    recipe = asm.build_recipe(31.4, (12, 0))
    assert recipe.load_in_4bit is False
    assert recipe.precision == "bf16"
    assert (recipe.batch_size, recipe.grad_accum, recipe.max_seq_len) == (8, 2, 2048)
    assert recipe.merge_adapter is True


@pytest.mark.parametrize("capability,precision,tf32", [
    ((6, 1),  "fp16", False),   # Pascal
    ((7, 5),  "fp16", False),   # Turing — GTX 1650, the case this exists for
    ((8, 0),  "bf16", True),    # Ampere, the threshold
    ((8, 6),  "bf16", True),
    ((12, 0), "bf16", True),    # Blackwell
    (None,    "fp16", False),   # unreadable -> assume the restrictive answer
])
def test_precision_follows_compute_capability(capability, precision, tf32):
    recipe = asm.build_recipe(8.0, capability)
    assert recipe.precision == precision
    assert recipe.tf32 is tf32


def test_cpu_recipe_never_asks_for_a_gpu_dtype():
    recipe = asm.build_recipe(None, None)
    assert recipe.precision == "fp32"    # fp16 on CPU is slower and unstable
    assert recipe.tf32 is False
    assert recipe.batch_size == 1


def test_quantised_runs_do_not_promise_a_merged_model():
    """peft cannot merge a LoRA losslessly back into 4-bit NF4 weights."""
    assert asm.build_recipe(4.0, (7, 5)).merge_adapter is False
    assert asm.build_recipe(31.4, (12, 0)).merge_adapter is True


def test_recipe_env_lines_are_shell_safe():
    lines = asm.build_recipe(4.0, (7, 5)).as_env_lines()
    keys = dict(line.split("=", 1) for line in lines)
    # run_pipeline.sh reads these with a case statement, one KEY=VALUE per line.
    assert all(" " not in line for line in lines)
    assert keys["LOAD_IN_4BIT"] == "1"
    assert keys["PRECISION"] == "fp16"
    assert keys["TF32"] == "0"
    assert keys["MERGE_ADAPTER"] == "0"


def test_num_workers_is_zero_on_windows(monkeypatch):
    """Spawned DataLoader workers cost more than they save under MSYS/Windows."""
    monkeypatch.setattr(asm.platform, "system", lambda: "Windows")
    assert asm.build_recipe(8.0, (8, 6)).dataloader_num_workers == 0
    monkeypatch.setattr(asm.platform, "system", lambda: "Linux")
    assert asm.build_recipe(8.0, (8, 6)).dataloader_num_workers == 4


def test_recipe_tiers_are_ordered_and_terminated():
    bounds = [row[0] for row in asm.RECIPE_TABLE]
    assert bounds[-1] is None
    finite = [b for b in bounds if b is not None]
    assert finite == sorted(finite)


# --- CLI: the recipe format run_pipeline.sh parses -------------------------
def test_recipe_format_is_key_value_lines(capsys):
    asm.main(["--simulate-vram-gb", "4.0", "--simulate-capability", "7.5",
              "--quiet", "--format", "recipe"])
    out = capsys.readouterr().out.strip().splitlines()
    parsed = dict(line.split("=", 1) for line in out)
    assert parsed["MODEL"] == "unsloth/Qwen2.5-1.5B-Instruct-bnb-4bit"
    assert parsed["CAPABILITY"] == "7.5"
    assert parsed["PRECISION"] == "fp16"
    assert parsed["BATCH_SIZE"] == "1"
    assert parsed["MAX_SEQ_LEN"] == "512"


def test_recipe_format_survives_having_no_gpu(capsys):
    """The CPU path must still emit every key the shell branches on."""
    asm.main(["--quiet", "--format", "recipe"])
    parsed = dict(
        line.split("=", 1)
        for line in capsys.readouterr().out.strip().splitlines()
    )
    for key in ("MODEL", "PRECISION", "BATCH_SIZE", "GRAD_ACCUM", "MAX_SEQ_LEN",
                "LORA_R", "OPTIM", "NUM_WORKERS", "ATTN_IMPL", "MERGE_ADAPTER", "TF32"):
        assert key in parsed, f"{key} missing — run_pipeline.sh reads it"


def test_bad_simulated_capability_is_rejected():
    with pytest.raises(SystemExit) as exc:
        asm.main(["--simulate-vram-gb", "8", "--simulate-capability", "turing"])
    assert exc.value.code == 2


def test_capability_probe_survives_missing_torch(monkeypatch):
    real_import = builtins.__import__

    def no_torch(name, *args, **kwargs):
        if name == "torch":
            raise ImportError("No module named 'torch'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_torch)
    assert asm.probe_capability() is None

"""
ai_module — Agentic AI subsystem for the async DAST scanner.

Components
----------
- dataset_generator : turn testbed telemetry JSONL into SFT/preference datasets
- train_qlora       : QLoRA / Unsloth fine-tuning entrypoint (RTX 5090 / sm_120)
- agent_inference   : async local inference client (TP/FP triage + payload synthesis)
- prompts/          : system prompts and reasoning guidelines for the security agent

The whole package is optional. Import failures of the heavy ML stack are deferred
to call time so the core scanner keeps working without `pip install .[ai]`.
"""

__all__ = ["dataset_generator", "train_qlora", "agent_inference"]

__version__ = "0.1.0"

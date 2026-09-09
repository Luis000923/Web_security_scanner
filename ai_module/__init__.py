"""
ai_module — Agentic AI subsystem for the async DAST scanner.

Components
----------
- dataset_generator      : turn testbed telemetry JSONL into SFT/preference datasets
- inject_cognitive_noise : "cognitive lobotomy" step — injects off-topic noise
                           rows labelled with the restricted-mode sentinel
- train_qlora            : QLoRA / native-bf16 fine-tuning entrypoint (RTX 5090 / sm_120)
- security_metrics       : TrainerCallback reporting FNR / FP-recall / refusal
                           accuracy at each eval round (not just eval_loss)
- agent_inference        : async local inference client (TP/FP triage + payload synthesis)
- structured_inference   : Outlines/pydantic-constrained typed decoding + the
                           shared taxonomy (TriageOut / PayloadOut / Verdict)
- evaluate_golden        : acceptance-gate harness — runs AgentClient over a
                           curated golden dataset and reports FNR / TP
                           degradation / FP-recall (see ../run_eval.sh)
- prompts/               : system prompts and reasoning guidelines for the security agent

The whole package is optional. Import failures of the heavy ML stack are deferred
to call time so the core scanner keeps working without `pip install .[ai]`.
"""

__all__ = [
    "dataset_generator", "inject_cognitive_noise", "train_qlora",
    "security_metrics", "agent_inference", "structured_inference",
    "evaluate_golden",
]

__version__ = "0.1.0"

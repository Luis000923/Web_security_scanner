"""Regression coverage for model errors during triage evaluation."""

import asyncio

from ai_module.agent_inference import AgentClient
from ai_module.evaluate_golden import ERROR_LABEL, GoldenRow, _evaluate_one, compute_metrics
from ai_module.structured_inference import parse_triage_with_status


def test_invalid_model_output_is_retried_and_excluded_from_metrics():
    async def run():
        client = AgentClient(backend="echo")
        calls = 0

        async def invalid(*args, **kwargs):
            nonlocal calls
            calls += 1
            return "not JSON"

        client._chat = invalid
        row = GoldenRow("one", {}, "TRUE_POSITIVE")
        result = await _evaluate_one(client, row, timeout=1, retries=1)
        assert calls == 2
        assert result.predicted == ERROR_LABEL
        assert "Unparseable model output" in result.error
        assert compute_metrics([result])["error_rate"] == 1.0

    asyncio.run(run())


def test_backend_failure_is_safe_for_scanner_and_error_for_evaluation():
    async def run():
        client = AgentClient(backend="echo")

        async def fail(*args, **kwargs):
            raise ConnectionError("offline")

        client._chat = fail
        triage = await client.triage_finding({})
        assert triage.verdict == "UNCERTAIN"
        assert triage.is_vulnerable
        assert "ConnectionError" in triage.error
        row = GoldenRow("one", {}, "TRUE_POSITIVE")
        result = await _evaluate_one(client, row, timeout=1, retries=0)
        assert result.predicted == ERROR_LABEL
        assert "ConnectionError" in result.error

    asyncio.run(run())


def test_valid_uncertain_output_is_a_prediction():
    async def run():
        client = AgentClient(backend="echo")
        row = GoldenRow("one", {}, "UNCERTAIN")
        result = await _evaluate_one(client, row, timeout=1, retries=0)
        assert result.predicted == "UNCERTAIN"
        assert not result.error

    asyncio.run(run())


def test_json_inside_text_handles_braces_in_reasoning():
    text = ('Result: {"verdict":"TRUE_POSITIVE","confidence":0.9,'
            '"reasoning":"The marker { is reflected.","next_step":"Check"} done')
    parsed, valid = parse_triage_with_status(text)
    assert valid
    assert parsed.verdict.value == "TRUE_POSITIVE"
    assert parsed.reasoning == "The marker { is reflected."


def test_json_prefix_is_opt_in_and_limited_to_deepseek_triage():
    class Tokenizer:
        def apply_chat_template(self, *args, **kwargs):
            return "assistant<think>\n"

    class Pipeline:
        tokenizer = Tokenizer()

        def __init__(self):
            self.prompts = []

        def __call__(self, prompt, **kwargs):
            self.prompts.append(prompt)
            assert kwargs["clean_up_tokenization_spaces"] is False
            return [{"generated_text": 'UNCERTAIN"}'}]

    client = AgentClient(backend="transformers", triage_json_prefix=True)
    pipeline = Pipeline()
    client._hf = pipeline
    assert client._generate_hf("system", "user", triage=True) == '{"verdict": "UNCERTAIN"}'
    assert pipeline.prompts[-1].endswith('<think>\n</think>\n{"verdict": "')
    client._generate_hf("system", "user", triage=False)
    assert pipeline.prompts[-1].endswith("<think>\n")
    client.triage_json_prefix = False
    client._generate_hf("system", "user", triage=True)
    assert pipeline.prompts[-1].endswith("<think>\n")

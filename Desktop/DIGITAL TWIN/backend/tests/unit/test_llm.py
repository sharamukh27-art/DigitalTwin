"""LLM wrapper and providers. No network: the mock provider and fake clients only."""

import asyncio
import json
from types import SimpleNamespace
from typing import Any

import pytest

from app.core.config import get_settings
from app.llm import client as llm_client
from app.llm.client import LLMMessage, ProviderError, ProviderResponse, complete
from app.llm.prompts import RULES, SYSTEM_PROMPT, extract_context, render_context, render_retry
from app.llm.providers import AnthropicProvider, MockProvider, UnconfiguredProvider, build_provider

HELLO = [LLMMessage(role="user", content="hello")]
SCHEMA = {"type": "object"}


def transient(kind: str = "server") -> ProviderError:
    return ProviderError(kind, f"{kind} failure", retryable=True)  # type: ignore[arg-type]


async def test_mock_provider_returns_text() -> None:
    result = await complete("system", HELLO)
    assert (result.ok, result.text, result.data, result.error) == (True, "mock response", None, None)
    assert (result.provider, result.model, result.attempts) == ("mock", "mock-1", 1)


async def test_json_schema_returns_parsed_data() -> None:
    result = await complete("s", HELLO, json_schema=SCHEMA, provider=MockProvider(script=['{"a": 1}']))
    assert (result.ok, result.data) == (True, {"a": 1})

    for bad in ("not json", "[1, 2]"):
        failed = await complete("s", HELLO, json_schema=SCHEMA, provider=MockProvider(script=[bad]))
        assert failed.ok is False and failed.error is not None
        assert (failed.error.kind, failed.text, failed.attempts) == ("invalid_json", bad, 1)


async def test_retryable_errors_are_retried_twice_then_succeed() -> None:
    provider = MockProvider(script=[transient("rate_limit"), transient("server"), "third time lucky"])
    result = await complete("s", HELLO, provider=provider)
    assert (result.ok, result.text, result.attempts) == (True, "third time lucky", 3)
    assert len(provider.calls) == 3


async def test_retries_are_exhausted_after_three_attempts() -> None:
    provider = MockProvider(script=[transient(), transient(), transient(), "never reached"])
    result = await complete("s", HELLO, provider=provider)
    assert result.ok is False and result.error is not None
    assert (result.error.kind, result.error.retryable, result.attempts) == ("server", True, 3)
    assert (result.text, len(provider.calls)) == (None, 3)


async def test_non_retryable_error_is_not_retried() -> None:
    provider = MockProvider(script=[ProviderError("auth", "bad key"), "never reached"])
    result = await complete("s", HELLO, provider=provider)
    assert result.error is not None
    assert (result.error.kind, result.error.message, result.attempts) == ("auth", "bad key", 1)


async def test_timeout_and_unexpected_errors_never_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    class Slow(MockProvider):
        async def generate(self, system: str, messages: list[LLMMessage], json_schema: Any) -> ProviderResponse:
            self.calls.append(messages)
            await asyncio.sleep(1)
            return ProviderResponse(text="late")

    class Broken(MockProvider):
        async def generate(self, system: str, messages: list[LLMMessage], json_schema: Any) -> ProviderResponse:
            raise KeyError("boom")

    monkeypatch.setattr(get_settings(), "llm_timeout_seconds", 0.01)
    slow = Slow()
    timed_out = await complete("s", HELLO, provider=slow)
    assert timed_out.error is not None
    assert (timed_out.error.kind, timed_out.attempts, len(slow.calls)) == ("timeout", 3, 3)

    broken = await complete("s", HELLO, provider=Broken())
    assert broken.error is not None
    assert (broken.error.kind, broken.error.message, broken.attempts) == ("unknown", "KeyError: 'boom'", 1)


async def test_backoff_doubles_between_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    waits: list[float] = []

    async def record(seconds: float) -> None:
        waits.append(seconds)

    monkeypatch.setattr(get_settings(), "llm_backoff_seconds", 0.5)
    monkeypatch.setattr(llm_client.asyncio, "sleep", record)
    await complete("s", HELLO, provider=MockProvider(script=[transient(), transient(), transient()]))
    assert waits == [0.5, 1.0]


def test_provider_selection(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = get_settings()
    assert isinstance(build_provider(settings), MockProvider)

    monkeypatch.setattr(settings, "llm_provider", "Anthropic")
    monkeypatch.setattr(settings, "llm_api_key", "test-key")
    claude = build_provider(settings)
    assert isinstance(claude, AnthropicProvider)
    assert (claude.name, claude.model) == ("anthropic", "claude-opus-5-5")
    monkeypatch.setattr(settings, "llm_model", "claude-sonnet-5-5")
    assert build_provider(settings).model == "claude-sonnet-5-5"

    monkeypatch.setattr(settings, "llm_provider", "gpt")
    assert isinstance(build_provider(settings), UnconfiguredProvider)


async def test_unsupported_provider_fails_cleanly() -> None:
    result = await complete("s", HELLO, provider=UnconfiguredProvider("gpt"))
    assert result.error is not None
    assert (result.error.kind, result.attempts) == ("not_configured", 1)
    assert "LLM_PROVIDER 'gpt' is not supported" in result.error.message


class FakeMessages:
    """Stands in for client.beta.messages and records the request."""

    def __init__(self, stop_reason: str = "end_turn", text: str = '{"ok": true}') -> None:
        self.request: dict[str, Any] = {}
        self.response = SimpleNamespace(
            stop_reason=stop_reason,
            stop_details=SimpleNamespace(category="cyber") if stop_reason == "refusal" else None,
            content=[SimpleNamespace(type="thinking", thinking=""), SimpleNamespace(type="text", text=text)],
            usage=SimpleNamespace(input_tokens=120, output_tokens=30),
        )

    async def create(self, **request: Any) -> Any:
        self.request = request
        return self.response


def claude_with(fake: FakeMessages) -> AnthropicProvider:
    provider = AnthropicProvider(model="claude-opus-5-5", api_key="test-key", timeout_seconds=5, max_tokens=1000)
    provider._client = SimpleNamespace(beta=SimpleNamespace(messages=fake))  # type: ignore[assignment]
    return provider


async def test_anthropic_request_shape_and_response_parsing() -> None:
    fake = FakeMessages()
    result = await complete("be grounded", HELLO, json_schema=SCHEMA, provider=claude_with(fake))

    assert fake.request == {
        "model": "claude-opus-5-5",
        "max_tokens": 1000,
        "system": "be grounded",
        "messages": [{"role": "user", "content": "hello"}],
        "betas": ["server-side-fallback-2026-07-01"],
        "fallbacks": "default",
        "output_config": {"format": {"type": "json_schema", "schema": SCHEMA}},
    }
    assert (result.ok, result.data, result.provider, result.model) == (True, {"ok": True}, "anthropic", "claude-opus-5-5")
    assert (result.usage.input_tokens, result.usage.output_tokens) == (120, 30)

    plain = FakeMessages(text="plain words")
    await complete("s", HELLO, provider=claude_with(plain))
    assert "output_config" not in plain.request


async def test_anthropic_refusal_and_truncation_are_typed_errors() -> None:
    refused = await complete("s", HELLO, provider=claude_with(FakeMessages(stop_reason="refusal")))
    assert refused.error is not None
    assert (refused.error.kind, refused.attempts) == ("refusal", 1)
    assert "cyber" in refused.error.message

    cut_off = await complete("s", HELLO, provider=claude_with(FakeMessages(stop_reason="max_tokens")))
    assert cut_off.error is not None and cut_off.error.kind == "truncated"


def test_system_prompt_states_the_rules_verbatim() -> None:
    assert RULES == (
        "Use ONLY facts in the FINDINGS JSON or the SOURCES. Do not invent hosts, controls, or numbers.",
        "Never alter detection, containment, risk score, or counts. Quote them exactly as given.",
        "Cite every claim drawn from a source as [S1], [S2]. Recommendations must each cite at least one source.",
        'If the sources do not cover a point, write "not covered by the provided sources".',
    )
    for rule in RULES:
        assert rule in SYSTEM_PROMPT


def test_context_block_round_trip() -> None:
    context = {"findings": {"containment": "contained"}, "risk": {"score": 3}, "sources": []}
    message = render_context(context)
    assert message.startswith("<context>\n{") and "</context>" in message
    assert extract_context(message) == context
    assert extract_context("no block here") is None
    assert extract_context("<context>{broken</context>") is None

    retry = render_retry(["summary must contain the risk score 39", "recommendation 1 has no citation"])
    assert "- summary must contain the risk score 39\n- recommendation 1 has no citation" in retry


async def test_mock_provider_builds_an_answer_from_the_context_block() -> None:
    context = {
        "findings": {
            "scenario_code": "S9", "containment": "contained", "first_detection_step": None,
            "time_to_detect_seconds": None, "blocking_controls": [], "detecting_controls": [],
            "missed_controls": [], "not_seen_gaps": [], "weakest_link": None, "killchain": [],
            "attack_depth": {"hops_achieved": 0, "total_steps": 2}, "blast_radius": {"asset_codes": []},
        },
        "risk": {"score": 0, "band": "low"},
        "sources": [],
    }
    result = await complete("s", [LLMMessage(role="user", content=render_context(context))], json_schema=SCHEMA)
    assert result.ok and result.data is not None
    assert set(result.data) == {"summary", "timeline", "why_caught_or_missed", "recommendations", "citations"}
    assert "containment contained and a risk score of 0 (low)" in result.data["summary"]
    assert json.loads(result.text or "") == result.data

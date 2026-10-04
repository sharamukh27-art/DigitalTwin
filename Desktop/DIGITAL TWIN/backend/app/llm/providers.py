"""LLM providers: Anthropic Claude, a deterministic mock, and a placeholder for bad config."""

import json
from collections.abc import Sequence
from typing import Any

import anthropic

from app.core.config import Settings
from app.llm.client import LLMMessage, LLMUsage, Provider, ProviderError, ProviderResponse
from app.llm.prompts import extract_context, extract_remediation
from app.llm.template import compose_explanation

FALLBACK_BETA = "server-side-fallback-2026-07-01"


class AnthropicProvider:
    """Claude through the official Anthropic SDK.

    Retries are left to the wrapper in client.py, so the SDK's own retries are
    turned off. Server-side refusal fallbacks are enabled: if the model declines a
    request for policy reasons, the API re-runs it on a fallback model in the same call.
    """

    name = "anthropic"

    def __init__(self, model: str, api_key: str, timeout_seconds: float, max_tokens: int) -> None:
        self.model = model
        self.max_tokens = max_tokens
        self._client = anthropic.AsyncAnthropic(
            api_key=api_key or None, timeout=timeout_seconds, max_retries=0
        )

    async def generate(
        self, system: str, messages: list[LLMMessage], json_schema: dict[str, Any] | None
    ) -> ProviderResponse:
        request: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system,
            "messages": [{"role": message.role, "content": message.content} for message in messages],
            "betas": [FALLBACK_BETA],
            "fallbacks": "default",
        }
        if json_schema is not None:
            request["output_config"] = {"format": {"type": "json_schema", "schema": json_schema}}
        try:
            response = await self._client.beta.messages.create(**request)
        except anthropic.RateLimitError as exc:
            raise ProviderError("rate_limit", exc.message, retryable=True) from exc
        except (anthropic.AuthenticationError, anthropic.PermissionDeniedError) as exc:
            raise ProviderError("auth", exc.message) from exc
        except (anthropic.BadRequestError, anthropic.NotFoundError) as exc:
            raise ProviderError("bad_request", exc.message) from exc
        except anthropic.APIStatusError as exc:
            retryable = exc.status_code >= 500 or exc.status_code in (408, 409)
            raise ProviderError("server", exc.message, retryable=retryable) from exc
        except anthropic.APITimeoutError as exc:
            raise ProviderError("timeout", "the request timed out", retryable=True) from exc
        except anthropic.APIConnectionError as exc:
            raise ProviderError("connection", str(exc), retryable=True) from exc
        except anthropic.AnthropicError as exc:
            raise ProviderError("not_configured", f"{type(exc).__name__}: {exc}") from exc

        if response.stop_reason == "refusal":
            category = getattr(getattr(response, "stop_details", None), "category", None) or "unspecified"
            raise ProviderError("refusal", f"the model declined the request ({category})")
        if response.stop_reason == "max_tokens":
            raise ProviderError("truncated", "the response was cut off at max_tokens")
        text = next((block.text for block in response.content if block.type == "text"), "")
        return ProviderResponse(
            text=text,
            usage=LLMUsage(
                input_tokens=response.usage.input_tokens, output_tokens=response.usage.output_tokens
            ),
        )


class MockProvider:
    """Deterministic provider for tests and offline use. Never contacts a network.

    With no script it reads the context block from the last user message and returns a
    valid explanation built from it; for a remediation block it returns the rule's own
    title and rationale. A script is a list of canned replies (strings) or
    errors (ProviderError) that are returned in order before that default takes over.
    """

    name = "mock"
    model = "mock-1"

    def __init__(self, script: Sequence[str | ProviderError] = ()) -> None:
        self.script: list[str | ProviderError] = list(script)
        self.calls: list[list[LLMMessage]] = []

    async def generate(
        self, system: str, messages: list[LLMMessage], json_schema: dict[str, Any] | None
    ) -> ProviderResponse:
        self.calls.append(list(messages))
        if self.script:
            reply = self.script.pop(0)
            if isinstance(reply, ProviderError):
                raise reply
            return ProviderResponse(text=reply, usage=LLMUsage(input_tokens=0, output_tokens=0))
        for message in reversed(messages):
            remediation = extract_remediation(message.content) if message.role == "user" else None
            if remediation is not None:
                facts = remediation.get("facts", {})
                return ProviderResponse(
                    text=json.dumps(
                        {"title": facts.get("template_title", ""), "rationale": facts.get("template_rationale", "")}
                    )
                )
        context = next(
            (
                found
                for message in reversed(messages)
                if message.role == "user" and (found := extract_context(message.content)) is not None
            ),
            None,
        )
        if context is None:
            return ProviderResponse(text="mock response")
        return ProviderResponse(text=json.dumps(compose_explanation(context)))


class UnconfiguredProvider:
    """Stands in when LLM_PROVIDER names something unknown. Every call fails cleanly."""

    model = "none"

    def __init__(self, name: str) -> None:
        self.name = name or "unset"

    async def generate(
        self, system: str, messages: list[LLMMessage], json_schema: dict[str, Any] | None
    ) -> ProviderResponse:
        raise ProviderError(
            "not_configured", f"LLM_PROVIDER '{self.name}' is not supported; use 'anthropic' or 'mock'"
        )


def build_provider(settings: Settings) -> Provider:
    """Create the provider named by LLM_PROVIDER."""
    name = settings.llm_provider.strip().lower()
    if name == "mock":
        return MockProvider()
    if name == "anthropic":
        return AnthropicProvider(
            model=settings.llm_model_name,
            api_key=settings.llm_api_key,
            timeout_seconds=settings.llm_timeout_seconds,
            max_tokens=settings.llm_max_tokens,
        )
    return UnconfiguredProvider(name)

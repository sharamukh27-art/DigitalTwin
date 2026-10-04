"""LLM wrapper: one `complete` call, providers chosen by LLM_PROVIDER, typed errors.

`complete` never raises. Every failure comes back as an LLMResult with `ok` false
and a typed LLMError, so callers can fall back deterministically.
"""

import asyncio
import json
import logging
from typing import Any, Literal, Protocol

from pydantic import BaseModel

from app.core.config import get_settings

logger = logging.getLogger(__name__)

ErrorKind = Literal[
    "timeout",
    "rate_limit",
    "server",
    "connection",
    "bad_request",
    "auth",
    "refusal",
    "truncated",
    "invalid_json",
    "not_configured",
    "unknown",
]


class LLMMessage(BaseModel):
    """One conversation turn sent to the model."""

    role: Literal["user", "assistant"]
    content: str


class LLMUsage(BaseModel):
    """Token counts reported by the provider."""

    input_tokens: int = 0
    output_tokens: int = 0


class LLMError(BaseModel):
    """Why a completion failed."""

    kind: ErrorKind
    message: str
    retryable: bool = False


class LLMResult(BaseModel):
    """Outcome of `complete`. Exactly one of `text` or `error` is set."""

    ok: bool
    text: str | None = None
    data: dict[str, Any] | None = None
    error: LLMError | None = None
    provider: str
    model: str
    attempts: int
    usage: LLMUsage = LLMUsage()


class ProviderResponse(BaseModel):
    """What a provider returns for one successful call."""

    text: str
    usage: LLMUsage = LLMUsage()


class ProviderError(Exception):
    """A provider call failed in a way the wrapper understands."""

    def __init__(self, kind: ErrorKind, message: str, retryable: bool = False) -> None:
        super().__init__(message)
        self.kind: ErrorKind = kind
        self.message = message
        self.retryable = retryable


class Provider(Protocol):
    """A model backend."""

    name: str
    model: str

    async def generate(
        self, system: str, messages: list[LLMMessage], json_schema: dict[str, Any] | None
    ) -> ProviderResponse:
        """Return the model's text. Raise ProviderError on failure."""
        ...


_provider: Provider | None = None


def get_provider() -> Provider:
    """Return the active provider, created from LLM_PROVIDER on first use."""
    global _provider
    if _provider is None:
        from app.llm.providers import build_provider

        _provider = build_provider(get_settings())
    return _provider


def set_provider(provider: Provider | None) -> None:
    """Replace the active provider. Used by tests; None re-reads the settings."""
    global _provider
    _provider = provider


async def complete(
    system: str,
    messages: list[LLMMessage],
    json_schema: dict[str, Any] | None = None,
    provider: Provider | None = None,
) -> LLMResult:
    """Ask the model for a completion.

    Each call is bounded by LLM_TIMEOUT_SECONDS. Retryable failures (timeout, rate
    limit, server and connection errors) are retried up to LLM_MAX_RETRIES times with
    exponential backoff. With `json_schema`, the text must parse as a JSON object and
    is returned in `data`. Never raises.
    """
    settings = get_settings()
    backend = provider or get_provider()
    max_attempts = settings.llm_max_retries + 1
    error = LLMError(kind="unknown", message="no attempt was made")
    attempts = 0

    for attempt in range(1, max_attempts + 1):
        attempts = attempt
        try:
            response = await asyncio.wait_for(
                backend.generate(system, messages, json_schema), timeout=settings.llm_timeout_seconds
            )
        except asyncio.TimeoutError:
            error = LLMError(
                kind="timeout",
                message=f"no response within {settings.llm_timeout_seconds} seconds",
                retryable=True,
            )
        except ProviderError as exc:
            error = LLMError(kind=exc.kind, message=exc.message, retryable=exc.retryable)
        except Exception as exc:  # noqa: BLE001 - the wrapper must never raise to its caller
            error = LLMError(kind="unknown", message=f"{type(exc).__name__}: {exc}")
        else:
            logger.info(
                "llm completion",
                extra={
                    "provider": backend.name,
                    "model": backend.model,
                    "attempt": attempt,
                    "input_tokens": response.usage.input_tokens,
                    "output_tokens": response.usage.output_tokens,
                },
            )
            data: dict[str, Any] | None = None
            if json_schema is not None:
                try:
                    parsed = json.loads(response.text)
                except json.JSONDecodeError as exc:
                    parsed = None
                    reason = f"response is not valid JSON: {exc}"
                else:
                    reason = "response JSON is not an object"
                if not isinstance(parsed, dict):
                    logger.warning("llm returned invalid json", extra={"provider": backend.name})
                    return LLMResult(
                        ok=False,
                        text=response.text,
                        error=LLMError(kind="invalid_json", message=reason),
                        provider=backend.name,
                        model=backend.model,
                        attempts=attempt,
                        usage=response.usage,
                    )
                data = parsed
            return LLMResult(
                ok=True,
                text=response.text,
                data=data,
                provider=backend.name,
                model=backend.model,
                attempts=attempt,
                usage=response.usage,
            )

        logger.warning(
            "llm call failed",
            extra={
                "provider": backend.name,
                "attempt": attempt,
                "error_kind": error.kind,
                "error_message": error.message,
                "retryable": error.retryable,
            },
        )
        if not error.retryable or attempt == max_attempts:
            break
        await asyncio.sleep(settings.llm_backoff_seconds * (2 ** (attempt - 1)))

    return LLMResult(
        ok=False, error=error, provider=backend.name, model=backend.model, attempts=attempts
    )

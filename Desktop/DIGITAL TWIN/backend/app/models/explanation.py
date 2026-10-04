"""Explanation models: the LLM output schema and the stored explanation."""

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.common import new_id, utcnow
from app.models.enums import EffortHint


class TimelineItem(BaseModel):
    """Plain-language explanation of one executed step."""

    model_config = ConfigDict(extra="forbid")

    step_order: int
    plain_explanation: str
    citation_ids: list[str] = Field(default_factory=list)


class Recommendation(BaseModel):
    """One recommended action. Must cite at least one source; the validator enforces that."""

    model_config = ConfigDict(extra="forbid")

    text: str
    related_control_code: str | None = None
    related_technique_id: str
    citation_ids: list[str] = Field(default_factory=list)
    effort_hint: EffortHint


class Citation(BaseModel):
    """A source referred to as [S1], [S2], ... in the explanation."""

    model_config = ConfigDict(extra="forbid")

    id: str
    source_name: str
    source_url: str


class ExplanationBody(BaseModel):
    """The JSON the LLM must return."""

    model_config = ConfigDict(extra="forbid")

    summary: str
    timeline: list[TimelineItem]
    why_caught_or_missed: str
    recommendations: list[Recommendation]
    citations: list[Citation]


class Explanation(ExplanationBody):
    """A stored explanation of one run, with how it was produced."""

    model_config = ConfigDict(extra="ignore")

    id: str = Field(default_factory=new_id)
    run_id: str
    network_id: str
    generated_without_llm: bool = False
    provider: str
    model: str
    attempts: int = 0
    validation_errors: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utcnow)

    @field_validator("created_at")
    @classmethod
    def _ensure_utc(cls, value: datetime) -> datetime:
        """Treat naive datetimes as UTC and convert aware ones to UTC."""
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def to_document(self) -> dict[str, Any]:
        """Return a MongoDB-ready dict: plain JSON values, native datetimes."""
        document = self.model_dump(mode="json")
        document["created_at"] = self.created_at
        return document


def _object(properties: dict[str, Any]) -> dict[str, Any]:
    """Build a closed JSON schema object in which every property is required."""
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties),
        "additionalProperties": False,
    }


_STRING: dict[str, Any] = {"type": "string"}
_STRING_LIST: dict[str, Any] = {"type": "array", "items": _STRING}

EXPLANATION_SCHEMA: dict[str, Any] = _object(
    {
        "summary": _STRING,
        "timeline": {
            "type": "array",
            "items": _object(
                {
                    "step_order": {"type": "integer"},
                    "plain_explanation": _STRING,
                    "citation_ids": _STRING_LIST,
                }
            ),
        },
        "why_caught_or_missed": _STRING,
        "recommendations": {
            "type": "array",
            "items": _object(
                {
                    "text": _STRING,
                    "related_control_code": {"anyOf": [_STRING, {"type": "null"}]},
                    "related_technique_id": _STRING,
                    "citation_ids": _STRING_LIST,
                    "effort_hint": {"type": "string", "enum": [item.value for item in EffortHint]},
                }
            ),
        },
        "citations": {
            "type": "array",
            "items": _object({"id": _STRING, "source_name": _STRING, "source_url": _STRING}),
        },
    }
)

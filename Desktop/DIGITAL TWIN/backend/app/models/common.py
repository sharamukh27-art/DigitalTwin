"""Shared model building blocks: ids, timestamps, constrained types, list pages."""

import uuid
from datetime import datetime, timezone
from typing import Annotated, Any, Generic, TypeVar

from pydantic import BaseModel, Field, StringConstraints, field_validator

T = TypeVar("T")

Code = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]
Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
PortNumber = Annotated[int, Field(ge=1, le=65535)]


def new_id() -> str:
    """Return a new UUID4 string."""
    return str(uuid.uuid4())


def utcnow() -> datetime:
    """Return the current UTC time, truncated to the millisecond precision MongoDB stores."""
    now = datetime.now(timezone.utc)
    return now.replace(microsecond=(now.microsecond // 1000) * 1000)


class StoredModel(BaseModel):
    """Fields present on every stored document."""

    id: str = Field(default_factory=new_id)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    @field_validator("created_at", "updated_at")
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
        document["updated_at"] = self.updated_at
        return document


class Page(BaseModel, Generic[T]):
    """Standard list response."""

    items: list[T]
    total: int


class ErrorDetail(BaseModel):
    """Inner object of the shared error format."""

    code: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    """Shared error format returned by every failing request."""

    error: ErrorDetail


def reject_nulls(model: BaseModel, nullable: frozenset[str]) -> None:
    """Raise ValueError when an update explicitly sets a non-nullable field to null."""
    for field in model.model_fields_set:
        if field not in nullable and getattr(model, field) is None:
            raise ValueError(f"{field} cannot be null")

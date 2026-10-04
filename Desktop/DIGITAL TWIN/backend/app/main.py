"""FastAPI application: wiring, lifecycle and the health endpoint."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.api import analysis, controls, explain, remediation, simulation, twin
from app.core import db
from app.core.config import get_settings
from app.core.errors import register_exception_handlers
from app.core.logging import configure_logging, install_request_logging

logger = logging.getLogger(__name__)


class HealthResponse(BaseModel):
    """Response of GET /health."""

    status: Literal["ok", "degraded"]
    mongo: Literal["ok", "down"]
    version: str


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Connect to MongoDB and create indexes on startup, disconnect on shutdown."""
    db.connect()
    try:
        await db.create_indexes()
    except Exception:  # noqa: BLE001 - the API still starts so /health can report mongo down
        logger.exception("could not create mongo indexes on startup")
    yield
    db.close()


def create_app() -> FastAPI:
    """Build the FastAPI application."""
    settings = get_settings()
    configure_logging(settings.log_level)

    app = FastAPI(title=settings.app_name, version=settings.app_version, lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    install_request_logging(app)
    register_exception_handlers(app)

    health_router = APIRouter(tags=["health"])

    @health_router.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        """Report API and MongoDB status."""
        mongo_ok = await db.ping()
        return HealthResponse(
            status="ok" if mongo_ok else "degraded",
            mongo="ok" if mongo_ok else "down",
            version=settings.app_version,
        )

    app.include_router(health_router, prefix=settings.api_prefix)
    app.include_router(twin.router, prefix=settings.api_prefix)
    app.include_router(controls.router, prefix=settings.api_prefix)
    app.include_router(simulation.router, prefix=settings.api_prefix)
    app.include_router(analysis.router, prefix=settings.api_prefix)
    app.include_router(explain.router, prefix=settings.api_prefix)
    app.include_router(remediation.router, prefix=settings.api_prefix)
    return app


app = create_app()

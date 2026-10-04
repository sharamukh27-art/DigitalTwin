"""Remediation API: generate, verify, bundle, decide, export and audit."""

from typing import Annotated, Literal

from fastapi import APIRouter, Query, status
from fastapi.responses import PlainTextResponse

from app.api.deps import NetworkDep, PaginationDep
from app.models.common import Page
from app.models.enums import RemediationStatus
from app.models.remediation import (
    AuditLog,
    BundleRequest,
    BundleResult,
    Remediation,
    RemediationUpdate,
)
from app.remediation import approval, repository, service, verify
from app.remediation.export import render_change_plan
from app.remediation.ranking import rank

router = APIRouter(tags=["remediation"])


@router.post(
    "/runs/{run_id}/remediations", response_model=Page[Remediation], status_code=status.HTTP_201_CREATED
)
async def generate_remediations(run_id: str) -> Page[Remediation]:
    """Generate candidate fixes for the gaps of a run. Safe to call again: existing fixes are reused."""
    items = await service.generate_for_run(run_id)
    return Page[Remediation](items=items, total=len(items))


@router.post("/remediations/verify-bundle", response_model=BundleResult)
async def verify_bundle(payload: BundleRequest) -> BundleResult:
    """Test several fixes together in one sandbox and report the combined effect."""
    return await verify.verify_bundle(payload.ids)


@router.post("/remediations/{remediation_id}/verify", response_model=Remediation)
async def verify_remediation(remediation_id: str) -> Remediation:
    """Test a fix on a sandbox copy against every scenario and store the result."""
    return await verify.verify(remediation_id)


@router.get("/remediations/{remediation_id}", response_model=Remediation)
async def get_remediation(remediation_id: str) -> Remediation:
    """Return one remediation."""
    return await repository.get_remediation(remediation_id)


@router.patch("/remediations/{remediation_id}", response_model=Remediation)
async def decide_remediation(remediation_id: str, payload: RemediationUpdate) -> Remediation:
    """Approve or reject a remediation.

    Approving applies the patch to the digital twin as a new network version and
    returns the remediation with status `applied`. Nothing is sent to a real device.
    """
    return await approval.decide(remediation_id, payload)


@router.get("/networks/{network_id}/remediations", response_model=Page[Remediation])
async def list_remediations(
    network: NetworkDep,
    page: PaginationDep,
    remediation_status: Annotated[RemediationStatus | None, Query(alias="status")] = None,
) -> Page[Remediation]:
    """List a network's remediations: verified ones first by priority, then the rest by age."""
    ranked = rank(await repository.list_remediations(network.id, remediation_status))
    return Page[Remediation](items=ranked[page.offset : page.offset + page.limit], total=len(ranked))


@router.get("/networks/{network_id}/remediations/export", response_class=PlainTextResponse)
async def export_change_plan(
    network: NetworkDep,
    export_format: Annotated[Literal["md"], Query(alias="format")] = "md",
) -> PlainTextResponse:
    """Return the change plan an administrator applies by hand, as markdown."""
    plan = render_change_plan(network, await repository.list_remediations(network.id))
    return PlainTextResponse(plan, media_type="text/markdown; charset=utf-8")


@router.get("/networks/{network_id}/audit-log", response_model=Page[AuditLog])
async def get_audit_log(network: NetworkDep, page: PaginationDep) -> Page[AuditLog]:
    """List a network's audit entries, oldest first."""
    items, total = await repository.list_audit(network.id, page.limit, page.offset)
    return Page[AuditLog](items=items, total=total)

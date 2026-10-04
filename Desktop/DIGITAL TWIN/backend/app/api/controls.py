"""Security control API: CRUD, control types, coverage matrix and debug evaluation."""

from typing import Annotated, Any

from fastapi import APIRouter, Query, Response, status
from pydantic import ValidationError

from app.api.deps import NetworkDep, PaginationDep
from app.controls import catalog, coverage, evaluator
from app.controls import repository as control_repository
from app.core.errors import ValidationFailed
from app.models.common import Page, utcnow
from app.models.control import (
    CONFIG_MODELS,
    ControlCreate,
    ControlRead,
    ControlUpdate,
    SecurityControl,
    placement_errors,
)
from app.models.enums import ControlType
from app.models.evaluation import (
    ControlTypeInfo,
    CoverageResponse,
    EvaluateRequest,
    EvaluateResponse,
    StepContext,
)
from app.twin import graph as twin_graph
from app.twin import repository as twin_repository
from app.twin import techniques
from app.twin.versioning import bump_version

router = APIRouter(tags=["controls"])


def _validation_details(exc: ValidationError) -> dict[str, Any]:
    """Convert a Pydantic error into the details block of the shared error format."""
    return {
        "errors": [
            {"loc": [str(part) for part in error["loc"]], "msg": error["msg"], "type": error["type"]}
            for error in exc.errors()
        ]
    }


async def _require_valid_placement(network_id: str, control: SecurityControl) -> None:
    """Raise ValidationFailed when the placement is unusable or names unknown assets."""
    placement = control.placement
    problems = placement_errors(
        placement.kind, placement.asset_ids, placement.zones, placement.services
    )
    if problems:
        raise ValidationFailed("Control placement is not valid", {"errors": problems})
    if placement.asset_ids:
        known = {asset.id for asset in await twin_repository.all_assets(network_id)}
        missing = [asset_id for asset_id in placement.asset_ids if asset_id not in known]
        if missing:
            raise ValidationFailed(
                "Placement assets must be assets of this network", {"missing_asset_ids": missing}
            )


@router.get("/control-types", response_model=list[ControlTypeInfo])
async def list_control_types() -> list[ControlTypeInfo]:
    """List every control type with the JSON schema of its config."""
    return [
        ControlTypeInfo(
            type=control_type,
            min_layer=catalog.min_layer(control_type),
            techniques=sorted(catalog.capabilities_for(control_type)),
            config_schema=CONFIG_MODELS[control_type].model_json_schema(),
        )
        for control_type in ControlType
    ]


@router.post(
    "/networks/{network_id}/controls",
    response_model=ControlRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_control(network: NetworkDep, payload: ControlCreate) -> SecurityControl:
    """Add a security control to a network. Increments the network version."""
    control = SecurityControl(network_id=network.id, **payload.model_dump())
    await _require_valid_placement(network.id, control)
    await control_repository.insert_control(control)
    await bump_version(network.id)
    return control


@router.get("/networks/{network_id}/controls", response_model=Page[ControlRead])
async def list_controls(
    network: NetworkDep,
    page: PaginationDep,
    control_type: Annotated[ControlType | None, Query(alias="type")] = None,
) -> Page[SecurityControl]:
    """List a network's controls, optionally filtered by type."""
    items, total = await control_repository.list_controls(
        network.id, page.limit, page.offset, control_type=control_type
    )
    return Page[SecurityControl](items=items, total=total)


@router.post("/networks/{network_id}/controls/evaluate", response_model=EvaluateResponse)
async def evaluate_step(network: NetworkDep, payload: EvaluateRequest) -> EvaluateResponse:
    """Debug: evaluate one step against every control of the network.

    Returns the connectivity decision and each control's capability result. The route
    defaults to the shortest path between the two assets.
    """
    technique = techniques.get(payload.technique_id)
    source = await twin_repository.get_asset(network.id, payload.source_asset_id)
    target = await twin_repository.get_asset(network.id, payload.target_asset_id)
    graph = await twin_graph.build_graph(network.id)

    if payload.path_asset_ids is not None:
        path = payload.path_asset_ids
        unknown = [asset_id for asset_id in path if asset_id not in graph]
        if unknown:
            raise ValidationFailed(
                "path_asset_ids must be assets of this network", {"missing_asset_ids": unknown}
            )
        if not path or path[0] != source.id or path[-1] != target.id:
            raise ValidationFailed("path_asset_ids must start at the source and end at the target")
        broken = [
            [first, second] for first, second in zip(path, path[1:]) if not graph.has_edge(first, second)
        ]
        if broken:
            raise ValidationFailed("path_asset_ids has hops with no link", {"hops": broken})
    else:
        shortest = twin_graph.shortest_path(graph, source.id, target.id)
        if shortest is None:
            raise ValidationFailed(
                f"No path from {source.code} to {target.code}",
                {"source_asset_id": source.id, "target_asset_id": target.id},
            )
        path = shortest.asset_ids

    link = None
    if len(path) == 2:
        parallel = graph[path[0]][path[1]]
        link_id = min(parallel, key=lambda key: parallel[key]["code"])
        link = await twin_repository.get_link(network.id, link_id)

    context = StepContext(
        technique_id=technique.id,
        source_asset=source,
        target_asset=target,
        link=link,
        path_asset_ids=path,
        layer=technique.osi_layer,
        protocol=payload.protocol,
        port=payload.port,
        service=payload.service,
    )
    controls = await control_repository.all_controls(network.id)
    return EvaluateResponse(
        context=context,
        connectivity=evaluator.check_connectivity(controls, context),
        results=evaluator.evaluate_all(controls, context),
    )


@router.get("/networks/{network_id}/controls/{control_id}", response_model=ControlRead)
async def get_control(network: NetworkDep, control_id: str) -> SecurityControl:
    """Return one control."""
    return await control_repository.get_control(network.id, control_id)


@router.patch("/networks/{network_id}/controls/{control_id}", response_model=ControlRead)
async def update_control(
    network: NetworkDep, control_id: str, payload: ControlUpdate
) -> SecurityControl:
    """Change fields of a control. Increments the network version.

    `config` keys are merged into the current config and the result is validated
    against the control's type.
    """
    current = await control_repository.get_control(network.id, control_id)
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        return current
    merged = {**current.model_dump(mode="json"), **changes, "updated_at": utcnow()}
    merged["created_at"] = current.created_at
    if "config" in changes:
        merged["config"] = {**current.config.model_dump(mode="json"), **changes["config"]}
    try:
        updated = SecurityControl.model_validate(merged)
    except ValidationError as exc:
        raise ValidationFailed("Control update is not valid", _validation_details(exc)) from exc
    await _require_valid_placement(network.id, updated)
    await control_repository.replace_control(updated)
    await bump_version(network.id)
    return updated


@router.delete(
    "/networks/{network_id}/controls/{control_id}", status_code=status.HTTP_204_NO_CONTENT
)
async def delete_control(network: NetworkDep, control_id: str) -> Response:
    """Delete a control. Increments the network version."""
    await control_repository.delete_control(network.id, control_id)
    await bump_version(network.id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/networks/{network_id}/coverage", response_model=CoverageResponse)
async def get_coverage(network: NetworkDep) -> CoverageResponse:
    """Return the technique coverage matrix of a network."""
    return await coverage.coverage(network.id)

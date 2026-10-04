"""Coverage matrix: which techniques could the network's controls catch?

The matrix ignores placement. It answers "do we own a tool that could catch this".
`placement_gaps` separately lists hosts and zones a deployed tool does not reach.
"""

from collections.abc import Sequence

from app.controls import catalog
from app.controls import repository as control_repository
from app.models.asset import Asset
from app.models.control import SecurityControl
from app.models.enums import (
    ZONES_BY_TRUST,
    AssetType,
    CapabilityAction,
    ControlType,
    CoverageStatus,
    PlacementKind,
    Zone,
)
from app.models.evaluation import CoverageCell, CoverageResponse, CoverageRow, PlacementGap
from app.twin import repository as twin_repository
from app.twin import techniques

STRONG_CONFIDENCE = 0.5
HIGH_CRITICALITY = 4

_STOPPING_ACTIONS = (CapabilityAction.DETECT, CapabilityAction.BLOCK)
_HOST_ASSET_TYPES = frozenset(
    {
        AssetType.WORKSTATION,
        AssetType.LAPTOP,
        AssetType.SERVER,
        AssetType.DATABASE,
        AssetType.DOMAIN_CONTROLLER,
        AssetType.FILE_SERVER,
        AssetType.WEB_SERVER,
    }
)


def build_cell(control: SecurityControl, technique_id: str) -> CoverageCell:
    """Return the matrix cell of one control for one technique."""
    capability = catalog.get_capability(control.type, technique_id)
    if capability is None:
        return CoverageCell(
            control_id=control.id, control_code=control.code, status=CoverageStatus.NONE
        )
    if not control.enabled:
        return CoverageCell(
            control_id=control.id,
            control_code=control.code,
            status=CoverageStatus.NONE,
            reason="control disabled",
        )
    action, downgraded_from = catalog.effective_action(capability, control.config)
    failures = catalog.failed_requirements(capability, control.config)
    return CoverageCell(
        control_id=control.id,
        control_code=control.code,
        action=action,
        confidence=capability.confidence,
        status=CoverageStatus.MISSED_REQUIREMENT if failures else CoverageStatus.ACTIVE,
        reason=f"{' and '.join(failures)} on {control.code}" if failures else None,
        downgraded_from=downgraded_from,
    )


def best_confidence(cells: Sequence[CoverageCell]) -> float | None:
    """Return the highest confidence among active detect/block cells, or None."""
    confidences = [
        cell.confidence
        for cell in cells
        if cell.status == CoverageStatus.ACTIVE and cell.action in _STOPPING_ACTIONS
    ]
    return max(confidences) if confidences else None


def find_placement_gaps(
    controls: Sequence[SecurityControl], assets: Sequence[Asset]
) -> list[PlacementGap]:
    """List hosts and zones that a deployed control type does not reach.

    Host gaps: for each control type deployed on hosts and present in the capability
    catalog, every endpoint or server with criticality 4 or 5 that it is not installed on.
    Sensor gaps: for each control type deployed as a sensor, every zone except the
    internet that holds assets but has no sensor.
    """
    host_coverage: dict[ControlType, set[str]] = {}
    sensor_coverage: dict[ControlType, set[Zone]] = {}
    for control in controls:
        if not control.enabled:
            continue
        if control.placement.kind == PlacementKind.HOST and catalog.capabilities_for(control.type):
            host_coverage.setdefault(control.type, set()).update(control.placement.asset_ids)
        elif control.placement.kind == PlacementKind.SENSOR:
            sensor_coverage.setdefault(control.type, set()).update(control.placement.zones)

    gaps: list[PlacementGap] = []
    ordered_assets = sorted(assets, key=lambda asset: asset.code)
    for control_type in sorted(host_coverage, key=lambda item: item.value):
        for asset in ordered_assets:
            if (
                asset.type in _HOST_ASSET_TYPES
                and asset.criticality >= HIGH_CRITICALITY
                and asset.id not in host_coverage[control_type]
            ):
                gaps.append(
                    PlacementGap(
                        kind=PlacementKind.HOST,
                        control_type=control_type,
                        asset_id=asset.id,
                        asset_code=asset.code,
                        reason=f"{asset.code} (criticality {asset.criticality}) "
                        f"has no {control_type.value}",
                    )
                )

    populated = {asset.zone for asset in assets} - {Zone.INTERNET}
    for control_type in sorted(sensor_coverage, key=lambda item: item.value):
        for zone in ZONES_BY_TRUST:
            if zone in populated and zone not in sensor_coverage[control_type]:
                gaps.append(
                    PlacementGap(
                        kind=PlacementKind.SENSOR,
                        control_type=control_type,
                        zone=zone,
                        reason=f"zone {zone.value} has no {control_type.value} sensor",
                    )
                )
    return gaps


def build_coverage(controls: Sequence[SecurityControl], assets: Sequence[Asset]) -> CoverageResponse:
    """Compute the coverage matrix from controls and assets already in memory.

    coverage_percent is the share of catalog techniques with at least one active
    detect or block cell at confidence 0.5 or higher, rounded to one decimal.
    """
    ordered = sorted(controls, key=lambda control: control.code)
    matrix: list[CoverageRow] = []
    uncovered: list[str] = []
    weak: list[str] = []
    strong = 0
    for technique in techniques.all():
        cells = [build_cell(control, technique.id) for control in ordered]
        matrix.append(
            CoverageRow(
                technique_id=technique.id,
                technique_name=technique.name,
                tactic=technique.tactic,
                cells=cells,
            )
        )
        best = best_confidence(cells)
        if best is None:
            uncovered.append(technique.id)
        elif best < STRONG_CONFIDENCE:
            weak.append(technique.id)
        else:
            strong += 1
    percent = round(100 * strong / len(matrix), 1) if matrix else 0.0
    return CoverageResponse(
        matrix=matrix,
        uncovered_techniques=uncovered,
        weakly_covered=weak,
        coverage_percent=percent,
        placement_gaps=find_placement_gaps(ordered, assets),
    )


async def coverage(network_id: str) -> CoverageResponse:
    """Return the coverage matrix of a network. Raises NotFound for unknown ids."""
    await twin_repository.get_network(network_id)
    controls = await control_repository.all_controls(network_id)
    assets = await twin_repository.all_assets(network_id)
    return build_coverage(controls, assets)

"""Which controls protect an asset, judged by placement alone."""

from collections.abc import Sequence

from app.models.asset import Asset
from app.models.control import SecurityControl
from app.models.enums import PlacementKind


def protecting_controls(asset: Asset, controls: Sequence[SecurityControl]) -> list[SecurityControl]:
    """Return the controls whose placement covers an asset, ordered by code.

    inline and host: the asset is listed. sensor: the asset's zone is watched.
    network_wide: always. identity controls protect services, not assets, and are
    never returned.
    """
    covering: list[SecurityControl] = []
    for control in controls:
        placement = control.placement
        if placement.kind in (PlacementKind.INLINE, PlacementKind.HOST):
            covers = asset.id in placement.asset_ids
        elif placement.kind == PlacementKind.SENSOR:
            covers = asset.zone in placement.zones
        else:
            covers = placement.kind == PlacementKind.NETWORK_WIDE
        if covers:
            covering.append(control)
    return sorted(covering, key=lambda control: control.code)

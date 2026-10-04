"""Deterministic canvas layout: one block per zone, ordered by trust level."""

from collections.abc import Sequence

from app.models.asset import Asset
from app.models.enums import ZONES_BY_TRUST, Zone
from app.models.twin_io import Position, ZoneGroup

COLUMN_WIDTH = 190.0
ROW_HEIGHT = 110.0
ZONE_GAP = 70.0
ROWS_PER_COLUMN = 5


def group_by_zone(assets: Sequence[Asset]) -> list[ZoneGroup]:
    """Group assets by zone. Zones are ordered by trust level, assets by code."""
    members: dict[Zone, list[Asset]] = {zone: [] for zone in ZONES_BY_TRUST}
    for asset in assets:
        members[asset.zone].append(asset)
    return [
        ZoneGroup(
            zone=zone,
            asset_ids=[asset.id for asset in sorted(members[zone], key=lambda item: item.code)],
        )
        for zone in ZONES_BY_TRUST
        if members[zone]
    ]


def compute_positions(assets: Sequence[Asset]) -> dict[str, Position]:
    """Return a position for every asset id.

    Zones are laid out left to right in trust order. Inside a zone, assets are placed
    in code order, top to bottom, five to a column, wrapping into further columns to
    the right. A zone is as wide as its columns, so a large zone does not make the
    canvas tall.
    """
    positions: dict[str, Position] = {}
    left = 0.0
    for group in group_by_zone(assets):
        for index, asset_id in enumerate(group.asset_ids):
            column, row = divmod(index, ROWS_PER_COLUMN)
            positions[asset_id] = Position(x=left + column * COLUMN_WIDTH, y=row * ROW_HEIGHT)
        columns = (len(group.asset_ids) - 1) // ROWS_PER_COLUMN + 1
        left += columns * COLUMN_WIDTH + ZONE_GAP
    return positions

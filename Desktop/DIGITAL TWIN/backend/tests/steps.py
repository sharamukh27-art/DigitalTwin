"""Helpers that build controls and step contexts for evaluator tests."""

from collections.abc import Sequence
from typing import Any

from app.models.asset import Asset
from app.models.control import Placement, SecurityControl
from app.models.evaluation import StepContext
from app.twin import techniques


def make_control(
    code: str,
    control_type: str,
    kind: str,
    config: dict[str, Any],
    assets: Sequence[Asset] = (),
    zones: Sequence[str] = (),
    services: Sequence[str] = (),
    enabled: bool = True,
) -> SecurityControl:
    """Build an in-memory control placed on the given assets, zones or services."""
    return SecurityControl(
        network_id="n",
        code=code,
        name=code,
        type=control_type,
        enabled=enabled,
        placement=Placement(
            kind=kind, asset_ids=[asset.id for asset in assets], zones=list(zones), services=list(services)
        ),
        config=config,
    )


def make_step(
    assets: dict[str, Asset],
    technique_id: str,
    path: Sequence[str],
    port: int | None = None,
    protocol: str = "any",
    service: str | None = None,
) -> StepContext:
    """Build a step along a path of asset codes. The layer comes from the technique catalog."""
    return StepContext(
        technique_id=technique_id,
        source_asset=assets[path[0]],
        target_asset=assets[path[-1]],
        path_asset_ids=[assets[code].id for code in path],
        layer=techniques.get(technique_id).osi_layer,
        protocol=protocol,
        port=port,
        service=service,
    )


INTERNET_TO_WEB = ["INTERNET", "FW-EDGE", "WEB-01"]
INTERNET_TO_VPN = ["INTERNET", "FW-EDGE", "VPN-01"]
INTERNET_TO_DB = ["INTERNET", "FW-EDGE", "FW-INT", "SW-CORE", "DB-01"]
INTERNET_TO_WS01 = ["INTERNET", "FW-EDGE", "FW-INT", "SW-CORE", "SW-ACCESS-1", "WS-01"]
WEB_TO_APP = ["WEB-01", "FW-EDGE", "FW-INT", "SW-CORE", "APP-01"]
WS01_TO_APP = ["WS-01", "SW-ACCESS-1", "SW-CORE", "APP-01"]
WS01_TO_FS = ["WS-01", "SW-ACCESS-1", "SW-CORE", "FS-01"]
WS01_TO_DB = ["WS-01", "SW-ACCESS-1", "SW-CORE", "DB-01"]
WS01_TO_WS02 = ["WS-01", "SW-ACCESS-1", "WS-02"]
WS01_TO_WS06 = ["WS-01", "SW-ACCESS-1", "SW-CORE", "SW-ACCESS-2", "WS-06"]
WS06_TO_WS07 = ["WS-06", "SW-ACCESS-2", "WS-07"]
GUEST_TO_AP = ["GUEST-DEV", "AP-01"]
GUEST_TO_WS06 = ["GUEST-DEV", "AP-01", "SW-ACCESS-2", "WS-06"]
GUEST_TO_DB = ["GUEST-DEV", "AP-01", "SW-ACCESS-2", "SW-CORE", "DB-01"]
ADMIN_TO_DB = ["ADMIN-01", "SW-CORE", "DB-01"]
DB_TO_INTERNET = ["DB-01", "SW-CORE", "FW-INT", "FW-EDGE", "INTERNET"]

"""Validation rules of the Pydantic models."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.models.asset import Asset, AssetCreate, AssetUpdate, Cve, Port
from app.models.enums import ZONE_TRUST, ZONES_BY_TRUST, Zone
from app.models.link import LinkCreate
from app.models.network import Network


def make_asset(**overrides: object) -> AssetCreate:
    fields: dict[str, object] = {"code": "A-1", "name": "Asset", "type": "server", "zone": "server"}
    fields.update(overrides)
    return AssetCreate.model_validate(fields)


def test_valid_asset_gets_defaults() -> None:
    asset = make_asset()
    assert asset.criticality == 3
    assert asset.open_ports == []
    assert asset.data_classification.value == "internal"


@pytest.mark.parametrize("mac", ["AA:BB:CC:DD:EE", "AA-BB-CC-DD-EE-FF", "GG:BB:CC:DD:EE:FF", "aabbccddeeff"])
def test_bad_mac_is_rejected(mac: str) -> None:
    with pytest.raises(ValidationError, match="MAC address"):
        make_asset(mac=mac)


def test_mac_is_normalised_to_upper_case() -> None:
    assert make_asset(mac="aa:bb:cc:dd:ee:ff").mac == "AA:BB:CC:DD:EE:FF"


@pytest.mark.parametrize("ip", ["10.0.0.256", "not-an-ip", "10.0.0", "::1"])
def test_bad_ip_is_rejected(ip: str) -> None:
    with pytest.raises(ValidationError, match="IPv4"):
        make_asset(ip=ip)


@pytest.mark.parametrize("cve_id", ["CVE-21-1234", "CVE-2021-123", "2021-12345", "CVE-2021-ABCD"])
def test_bad_cve_is_rejected(cve_id: str) -> None:
    with pytest.raises(ValidationError, match="CVE id"):
        Cve(id=cve_id, cvss=5.0, description="x")


def test_cve_accepts_long_sequence_numbers() -> None:
    assert Cve(id="CVE-2021-1234567", cvss=9.8, description="x").id == "CVE-2021-1234567"


@pytest.mark.parametrize("cvss", [-0.1, 10.1])
def test_cvss_out_of_range_is_rejected(cvss: float) -> None:
    with pytest.raises(ValidationError):
        Cve(id="CVE-2021-1234", cvss=cvss, description="x")


@pytest.mark.parametrize("criticality", [0, 6])
def test_criticality_out_of_range_is_rejected(criticality: int) -> None:
    with pytest.raises(ValidationError):
        make_asset(criticality=criticality)


@pytest.mark.parametrize("port", [0, 65536])
def test_port_out_of_range_is_rejected(port: int) -> None:
    with pytest.raises(ValidationError):
        Port(port=port, protocol="tcp", service="x")


def test_unknown_zone_and_type_are_rejected() -> None:
    with pytest.raises(ValidationError):
        make_asset(zone="moon")
    with pytest.raises(ValidationError):
        make_asset(type="toaster")


def test_asset_update_rejects_null_for_required_field_but_allows_nullable() -> None:
    with pytest.raises(ValidationError, match="name cannot be null"):
        AssetUpdate.model_validate({"name": None})
    assert AssetUpdate.model_validate({"ip": None}).model_dump(exclude_unset=True) == {"ip": None}


def test_self_link_is_rejected() -> None:
    with pytest.raises(ValidationError, match="itself"):
        LinkCreate(code="L-1", source_asset_id="a", target_asset_id="a", type="ethernet")


def test_link_defaults() -> None:
    link = LinkCreate(code="L-1", source_asset_id="a", target_asset_id="b", type="ethernet")
    assert [protocol.value for protocol in link.allowed_protocols] == ["any"]
    assert link.allowed_ports == []
    assert link.bidirectional is True


def test_network_defaults() -> None:
    network = Network(name="n")
    assert network.version == 1
    assert network.is_sandbox is False
    assert network.parent_network_id is None
    assert network.created_at.tzinfo is not None


def test_stored_model_makes_naive_datetimes_utc() -> None:
    asset = Asset(
        network_id="n",
        code="A-1",
        name="Asset",
        type="server",
        zone="server",
        created_at=datetime(2026, 1, 1, 12, 0, 0),
    )
    assert asset.created_at == datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def test_zone_trust_levels() -> None:
    assert ZONE_TRUST == {
        Zone.INTERNET: 0,
        Zone.GUEST: 10,
        Zone.DMZ: 30,
        Zone.CORPORATE: 60,
        Zone.SERVER: 70,
        Zone.MANAGEMENT: 90,
    }
    assert [zone.value for zone in ZONES_BY_TRUST] == [
        "internet",
        "guest",
        "dmz",
        "corporate",
        "server",
        "management",
    ]

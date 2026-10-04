"""Control CRUD endpoints and the control type listing."""

from typing import Any

import pytest
import pytest_asyncio
from httpx import AsyncClient

from tests.conftest import API, create_asset, create_network, network_version
from tests.unit.test_control_models import BAD_CONFIGS, GOOD_CONFIGS


@pytest_asyncio.fixture
async def net(client: AsyncClient) -> dict[str, Any]:
    """A network with two assets and no controls."""
    network = await create_network(client)
    first = await create_asset(client, network["id"], code="A")
    second = await create_asset(client, network["id"], code="B")
    return {
        "id": network["id"],
        "a": first["id"],
        "b": second["id"],
        "url": f"{API}/networks/{network['id']}/controls",
    }


def control_body(control_type: str = "edr", code: str = "C-1", **overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "code": code,
        "name": f"Control {code}",
        "type": control_type,
        "placement": {"kind": "network_wide"},
        "config": GOOD_CONFIGS[control_type],
    }
    body.update(overrides)
    return body


@pytest.mark.parametrize("control_type", sorted(GOOD_CONFIGS))
async def test_every_type_can_be_created(client: AsyncClient, net: dict[str, Any], control_type: str) -> None:
    before = await network_version(client, net["id"])
    response = await client.post(net["url"], json=control_body(control_type))
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["type"] == control_type
    assert body["network_id"] == net["id"]
    assert body["enabled"] is True
    for key, value in GOOD_CONFIGS[control_type].items():
        if not isinstance(value, list) or not value or not isinstance(value[0], dict):
            assert body["config"][key] == value
    assert await network_version(client, net["id"]) == before + 1

    fetched = await client.get(f"{net['url']}/{body['id']}")
    assert fetched.json() == body


@pytest.mark.parametrize("control_type", sorted(BAD_CONFIGS))
async def test_every_type_rejects_a_bad_config(client: AsyncClient, net: dict[str, Any], control_type: str) -> None:
    before = await network_version(client, net["id"])
    response = await client.post(net["url"], json=control_body(control_type, config=BAD_CONFIGS[control_type]))
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "VALIDATION_FAILED"
    assert "config" in error["details"]["errors"][0]["msg"]
    assert await network_version(client, net["id"]) == before
    assert (await client.get(net["url"])).json()["total"] == 0


async def test_create_validation_errors(client: AsyncClient, net: dict[str, Any]) -> None:
    for body in (
        control_body(type="antivirus"),
        control_body("edr", config=GOOD_CONFIGS["firewall"]),
        control_body(placement={"kind": "host"}),
        control_body(placement={"kind": "sensor"}),
        control_body(placement={"kind": "identity"}),
        control_body(placement={"kind": "orbital"}),
        control_body(placement={"kind": "host", "asset_ids": ["missing-asset"]}),
        {"code": "C-1", "name": "no config", "type": "edr", "placement": {"kind": "network_wide"}},
    ):
        response = await client.post(net["url"], json=body)
        assert response.status_code == 422, body
    assert await network_version(client, net["id"]) == 3


async def test_placement_asset_must_belong_to_the_network(client: AsyncClient, net: dict[str, Any]) -> None:
    other = await create_network(client, "other")
    foreign = await create_asset(client, other["id"], code="X")
    response = await client.post(
        net["url"], json=control_body(placement={"kind": "host", "asset_ids": [foreign["id"]]})
    )
    assert response.status_code == 422
    assert response.json()["error"]["details"] == {"missing_asset_ids": [foreign["id"]]}


async def test_duplicate_code_is_409(client: AsyncClient, net: dict[str, Any]) -> None:
    assert (await client.post(net["url"], json=control_body())).status_code == 201
    response = await client.post(net["url"], json=control_body("waf"))
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "CONFLICT"


async def test_unknown_network_and_control_are_404(client: AsyncClient, net: dict[str, Any]) -> None:
    missing_network = f"{API}/networks/missing/controls"
    assert (await client.post(missing_network, json=control_body())).status_code == 404
    assert (await client.get(missing_network)).status_code == 404
    assert (await client.get(f"{net['url']}/missing")).status_code == 404
    assert (await client.patch(f"{net['url']}/missing", json={"enabled": False})).status_code == 404
    assert (await client.delete(f"{net['url']}/missing")).status_code == 404


async def test_list_with_type_filter(client: AsyncClient, acme_id: str) -> None:
    url = f"{API}/networks/{acme_id}/controls"
    everything = (await client.get(url)).json()
    assert everything["total"] == 14
    codes = [item["code"] for item in everything["items"]]
    assert codes == sorted(codes)

    firewalls = (await client.get(url, params={"type": "firewall"})).json()
    assert [item["code"] for item in firewalls["items"]] == ["FW-EDGE", "FW-INT"]

    page = (await client.get(url, params={"limit": 5, "offset": 10})).json()
    assert (page["total"], len(page["items"])) == (14, 4)

    assert (await client.get(url, params={"type": "dlp"})).json() == {"items": [], "total": 0}
    assert (await client.get(url, params={"type": "antivirus"})).status_code == 422


async def test_patch_merges_config_and_bumps_version(client: AsyncClient, acme_id: str) -> None:
    url = f"{API}/networks/{acme_id}/controls"
    swsec = next(item for item in (await client.get(url)).json()["items"] if item["code"] == "SWSEC-2")
    before = await network_version(client, acme_id)

    response = await client.patch(f"{url}/{swsec['id']}", json={"config": {"dynamic_arp_inspection": True}})
    assert response.status_code == 200
    body = response.json()
    assert body["config"] == {**swsec["config"], "dynamic_arp_inspection": True}
    assert body["placement"] == swsec["placement"]
    assert body["created_at"] == swsec["created_at"]
    assert await network_version(client, acme_id) == before + 1

    disabled = await client.patch(f"{url}/{swsec['id']}", json={"enabled": False, "name": "Off"})
    assert (disabled.json()["enabled"], disabled.json()["name"]) == (False, "Off")
    assert disabled.json()["config"]["dynamic_arp_inspection"] is True
    assert await network_version(client, acme_id) == before + 2


async def test_patch_errors_do_not_bump_version(client: AsyncClient, acme_id: str) -> None:
    url = f"{API}/networks/{acme_id}/controls"
    items = {item["code"]: item for item in (await client.get(url)).json()["items"]}
    edr = f"{url}/{items['EDR-01']['id']}"
    before = await network_version(client, acme_id)

    bad_value = await client.patch(edr, json={"config": {"mode": "sometimes"}})
    assert bad_value.status_code == 422
    assert "config.mode" in bad_value.json()["error"]["details"]["errors"][0]["msg"]
    assert (await client.patch(edr, json={"config": {"rules": []}})).status_code == 422
    assert (await client.patch(edr, json={"enabled": None})).status_code == 422
    assert (await client.patch(edr, json={"placement": {"kind": "host", "asset_ids": []}})).status_code == 422
    assert (await client.patch(edr, json={"placement": {"kind": "host", "asset_ids": ["nope"]}})).status_code == 422
    assert (await client.patch(edr, json={"code": "WAF-01"})).status_code == 409

    assert await network_version(client, acme_id) == before
    assert (await client.get(edr)).json() == items["EDR-01"]


async def test_delete_control_bumps_version(client: AsyncClient, net: dict[str, Any]) -> None:
    created = (await client.post(net["url"], json=control_body())).json()
    before = await network_version(client, net["id"])
    url = f"{net['url']}/{created['id']}"

    assert (await client.delete(url)).status_code == 204
    assert (await client.get(url)).status_code == 404
    assert await network_version(client, net["id"]) == before + 1


async def test_deleting_an_asset_removes_it_from_placements(
    client: AsyncClient, acme_id: str, acme_codes: dict[str, str]
) -> None:
    url = f"{API}/networks/{acme_id}/controls"
    assert (await client.delete(f"{API}/networks/{acme_id}/assets/{acme_codes['WS-01']}")).status_code == 204
    assert (await client.delete(f"{API}/networks/{acme_id}/assets/{acme_codes['WEB-01']}")).status_code == 204

    items = {item["code"]: item for item in (await client.get(url)).json()["items"]}
    assert acme_codes["WS-01"] not in items["EDR-01"]["placement"]["asset_ids"]
    assert len(items["EDR-01"]["placement"]["asset_ids"]) == 11
    assert items["WAF-01"]["placement"]["asset_ids"] == []
    assert (await client.get(f"{API}/networks/{acme_id}/coverage")).status_code == 200


async def test_control_types(client: AsyncClient) -> None:
    response = await client.get(f"{API}/control-types")
    assert response.status_code == 200
    types = {item["type"]: item for item in response.json()}
    assert set(types) == set(GOOD_CONFIGS)

    firewall = types["firewall"]
    assert firewall["min_layer"] == 3
    assert firewall["techniques"] == ["T1046"]
    assert set(firewall["config_schema"]["properties"]) == {"rules", "default_action", "logging"}
    assert set(firewall["config_schema"]["required"]) == {"default_action", "logging"}

    assert types["edr"]["config_schema"]["additionalProperties"] is False
    assert types["backup"]["techniques"] == []
    assert types["switch_security"]["techniques"] == ["T1557.002", "T1599"]

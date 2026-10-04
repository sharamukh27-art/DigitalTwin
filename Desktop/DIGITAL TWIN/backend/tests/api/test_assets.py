"""Asset CRUD endpoints."""

from httpx import AsyncClient

from tests.conftest import API, asset_payload, create_asset, create_network, network_version


async def test_create_asset_bumps_version(client: AsyncClient) -> None:
    network = await create_network(client)
    payload = asset_payload(
        "WEB-01",
        type="web_server",
        zone="dmz",
        ip="172.16.1.10",
        mac="aa:bb:cc:dd:ee:ff",
        open_ports=[{"port": 443, "protocol": "tcp", "service": "https", "version": "nginx 1.18.0"}],
        known_cves=[{"id": "CVE-2021-23017", "cvss": 7.5, "description": "nginx resolver"}],
    )
    response = await client.post(f"{API}/networks/{network['id']}/assets", json=payload)
    assert response.status_code == 201
    body = response.json()
    assert body["network_id"] == network["id"]
    assert body["mac"] == "AA:BB:CC:DD:EE:FF"
    assert body["open_ports"][0]["port"] == 443
    assert body["known_cves"][0]["cvss"] == 7.5
    assert body["data_classification"] == "internal"
    assert await network_version(client, network["id"]) == 2


async def test_create_asset_validation_is_422(client: AsyncClient) -> None:
    network = await create_network(client)
    url = f"{API}/networks/{network['id']}/assets"
    for bad in (
        {"mac": "bad"},
        {"ip": "300.1.1.1"},
        {"criticality": 6},
        {"zone": "moon"},
        {"known_cves": [{"id": "CVE-1", "cvss": 5, "description": "x"}]},
        {"open_ports": [{"port": 70000, "protocol": "tcp", "service": "x"}]},
    ):
        response = await client.post(url, json=asset_payload(**bad))
        assert response.status_code == 422, bad
        assert response.json()["error"]["code"] == "VALIDATION_FAILED"
    assert await network_version(client, network["id"]) == 1


async def test_create_asset_conflicts_are_409(client: AsyncClient) -> None:
    network = await create_network(client)
    url = f"{API}/networks/{network['id']}/assets"
    await create_asset(client, network["id"], code="A", ip="10.0.0.1")

    duplicate_code = await client.post(url, json=asset_payload("A"))
    assert duplicate_code.status_code == 409
    assert duplicate_code.json()["error"]["code"] == "CONFLICT"

    duplicate_ip = await client.post(url, json=asset_payload("B", ip="10.0.0.1"))
    assert duplicate_ip.status_code == 409
    assert await network_version(client, network["id"]) == 2


async def test_same_code_is_allowed_in_another_network(client: AsyncClient) -> None:
    first = await create_network(client, "one")
    second = await create_network(client, "two")
    await create_asset(client, first["id"], code="A", ip="10.0.0.1")
    await create_asset(client, second["id"], code="A", ip="10.0.0.1")


async def test_create_asset_in_unknown_network_is_404(client: AsyncClient) -> None:
    response = await client.post(f"{API}/networks/missing/assets", json=asset_payload())
    assert response.status_code == 404


async def test_list_assets_with_filters(client: AsyncClient, acme_id: str) -> None:
    url = f"{API}/networks/{acme_id}/assets"

    everything = (await client.get(url)).json()
    assert everything["total"] == 25
    assert len(everything["items"]) == 25

    page = (await client.get(url, params={"limit": 10, "offset": 20})).json()
    assert page["total"] == 25
    assert len(page["items"]) == 5

    dmz = (await client.get(url, params={"zone": "dmz"})).json()
    assert sorted(item["code"] for item in dmz["items"]) == ["FW-EDGE", "VPN-01", "WEB-01"]

    workstations = (await client.get(url, params={"type": "workstation"})).json()
    assert workstations["total"] == 11

    both = (await client.get(url, params={"zone": "corporate", "type": "workstation"})).json()
    assert both["total"] == 10

    assert (await client.get(url, params={"zone": "moon"})).status_code == 422
    assert (await client.get(f"{API}/networks/missing/assets")).status_code == 404


async def test_get_asset(client: AsyncClient, acme_id: str, acme_codes: dict[str, str]) -> None:
    response = await client.get(f"{API}/networks/{acme_id}/assets/{acme_codes['DB-01']}")
    assert response.status_code == 200
    body = response.json()
    assert (body["code"], body["criticality"], body["data_classification"]) == ("DB-01", 5, "restricted")

    assert (await client.get(f"{API}/networks/{acme_id}/assets/missing")).status_code == 404


async def test_asset_of_another_network_is_404(
    client: AsyncClient, acme_id: str, acme_codes: dict[str, str]
) -> None:
    other = await create_network(client)
    response = await client.get(f"{API}/networks/{other['id']}/assets/{acme_codes['DB-01']}")
    assert response.status_code == 404


async def test_patch_asset_bumps_version_by_one(
    client: AsyncClient, acme_id: str, acme_codes: dict[str, str]
) -> None:
    url = f"{API}/networks/{acme_id}/assets/{acme_codes['WS-01']}"
    before = await network_version(client, acme_id)

    response = await client.patch(url, json={"criticality": 4, "vlan": None, "tags": ["patched"]})
    assert response.status_code == 200
    body = response.json()
    assert (body["criticality"], body["vlan"], body["tags"]) == (4, None, ["patched"])
    assert body["os"] == "Windows"
    assert body["updated_at"] >= body["created_at"]

    assert await network_version(client, acme_id) == before + 1
    assert (await client.get(url)).json() == body


async def test_patch_asset_errors(
    client: AsyncClient, acme_id: str, acme_codes: dict[str, str]
) -> None:
    url = f"{API}/networks/{acme_id}/assets/{acme_codes['WS-01']}"
    before = await network_version(client, acme_id)

    assert (await client.patch(url, json={"criticality": 6})).status_code == 422
    assert (await client.patch(url, json={"mac": "bad"})).status_code == 422
    assert (await client.patch(url, json={"name": None})).status_code == 422
    assert (await client.patch(url, json={"code": "WS-02"})).status_code == 409
    assert (await client.patch(url, json={"ip": "10.0.20.20"})).status_code == 409
    missing = await client.patch(f"{API}/networks/{acme_id}/assets/missing", json={"owner": "x"})
    assert missing.status_code == 404

    assert await network_version(client, acme_id) == before


async def test_delete_asset_removes_its_links(
    client: AsyncClient, acme_id: str, acme_codes: dict[str, str]
) -> None:
    switch_id = acme_codes["SW-ACCESS-1"]
    before = await network_version(client, acme_id)

    response = await client.delete(f"{API}/networks/{acme_id}/assets/{switch_id}")
    assert response.status_code == 204

    assert (await client.get(f"{API}/networks/{acme_id}/assets/{switch_id}")).status_code == 404
    links = (await client.get(f"{API}/networks/{acme_id}/links")).json()
    assert links["total"] == 24 - 6
    assert all(
        switch_id not in (link["source_asset_id"], link["target_asset_id"]) for link in links["items"]
    )
    assert await network_version(client, acme_id) == before + 1


async def test_delete_unknown_asset_is_404(client: AsyncClient, acme_id: str) -> None:
    assert (await client.delete(f"{API}/networks/{acme_id}/assets/missing")).status_code == 404

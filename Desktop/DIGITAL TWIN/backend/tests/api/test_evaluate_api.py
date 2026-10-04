"""Debug evaluate endpoint."""

from typing import Any

from httpx import AsyncClient

from tests.conftest import API

Codes = dict[str, str]


async def evaluate(client: AsyncClient, network_id: str, **body: Any) -> Any:
    return await client.post(f"{API}/networks/{network_id}/controls/evaluate", json=body)


def outcomes(body: dict[str, Any]) -> dict[str, str]:
    return {item["control_code"]: item["outcome"] for item in body["results"]}


async def test_internet_to_web_is_allowed_and_only_detected(
    client: AsyncClient, acme_id: str, acme_codes: Codes
) -> None:
    response = await evaluate(
        client, acme_id,
        technique_id="T1190", source_asset_id=acme_codes["INTERNET"], target_asset_id=acme_codes["WEB-01"], port=443,
    )
    assert response.status_code == 200
    body = response.json()

    assert body["connectivity"]["allowed"] is True
    assert body["connectivity"]["rule_index"] == 0
    assert body["context"]["layer"] == 7
    assert body["context"]["path_asset_ids"] == [acme_codes[code] for code in ("INTERNET", "FW-EDGE", "WEB-01")]
    assert body["context"]["link"] is None

    assert len(body["results"]) == 14
    assert [(item["control_code"], item["outcome"], item["confidence"]) for item in body["results"][:2]] == [
        ("WAF-01", "detected", 0.8),
        ("IDS-01", "detected", 0.6),
    ]
    assert "blocked" not in outcomes(body).values()


async def test_internet_to_database_is_denied(client: AsyncClient, acme_id: str, acme_codes: Codes) -> None:
    response = await evaluate(
        client, acme_id,
        technique_id="T1190", source_asset_id=acme_codes["INTERNET"], target_asset_id=acme_codes["DB-01"], port=5432,
    )
    connectivity = response.json()["connectivity"]
    assert connectivity["allowed"] is False
    assert connectivity["rule_index"] is None
    assert connectivity["reason"].startswith("FW-EDGE has no rule")


async def test_flipping_dai_changes_missed_to_blocked(
    client: AsyncClient, acme_id: str, acme_codes: Codes
) -> None:
    step = {
        "technique_id": "T1557.002",
        "source_asset_id": acme_codes["WS-06"],
        "target_asset_id": acme_codes["WS-07"],
        "protocol": "any",
    }
    before = (await evaluate(client, acme_id, **step)).json()
    assert before["context"]["layer"] == 2
    assert before["connectivity"]["allowed"] is True
    assert outcomes(before)["SWSEC-2"] == "missed"
    assert outcomes(before)["SWSEC-1"] == "not_applicable"
    assert outcomes(before)["FW-INT"] == "not_applicable"
    missed = next(item for item in before["results"] if item["control_code"] == "SWSEC-2")
    assert missed["reason"] == "dynamic_arp_inspection is false on SWSEC-2"

    controls_url = f"{API}/networks/{acme_id}/controls"
    swsec = next(item for item in (await client.get(controls_url)).json()["items"] if item["code"] == "SWSEC-2")
    patched = await client.patch(f"{controls_url}/{swsec['id']}", json={"config": {"dynamic_arp_inspection": True}})
    assert patched.status_code == 200

    after = (await evaluate(client, acme_id, **step)).json()
    assert outcomes(after)["SWSEC-2"] == "blocked"
    assert after["results"][0]["control_code"] == "SWSEC-2"
    assert after["results"][0]["confidence"] == 0.9


async def test_direct_hop_includes_its_link_and_same_host_step_works(
    client: AsyncClient, acme_id: str, acme_codes: Codes
) -> None:
    direct = await evaluate(
        client, acme_id,
        technique_id="T1599", source_asset_id=acme_codes["GUEST-DEV"], target_asset_id=acme_codes["AP-01"],
    )
    assert direct.json()["context"]["link"]["code"] == "L-24"
    assert outcomes(direct.json())["NAC-01"] == "missed"

    local = await evaluate(
        client, acme_id,
        technique_id="T1486", source_asset_id=acme_codes["FS-01"], target_asset_id=acme_codes["FS-01"],
    )
    assert local.status_code == 200
    assert local.json()["context"]["path_asset_ids"] == [acme_codes["FS-01"]]
    assert outcomes(local.json())["EDR-01"] == "not_applicable"


async def test_explicit_path(client: AsyncClient, acme_id: str, acme_codes: Codes) -> None:
    path = [acme_codes[code] for code in ("INTERNET", "FW-EDGE", "VPN-01")]
    response = await evaluate(
        client, acme_id,
        technique_id="T1133", source_asset_id=path[0], target_asset_id=path[-1],
        port=443, service="vpn", path_asset_ids=path,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["connectivity"]["allowed"] is True
    assert outcomes(body)["MFA-01"] == "not_applicable"

    for bad_path in (
        [path[0], path[2]],
        [path[1], path[2]],
        [path[0], "missing", path[2]],
        [],
    ):
        rejected = await evaluate(
            client, acme_id,
            technique_id="T1133", source_asset_id=path[0], target_asset_id=path[-1], path_asset_ids=bad_path,
        )
        assert rejected.status_code == 422, bad_path


async def test_evaluate_errors(client: AsyncClient, acme_id: str, acme_codes: Codes) -> None:
    source, target = acme_codes["INTERNET"], acme_codes["WEB-01"]

    unknown_technique = await evaluate(client, acme_id, technique_id="T9999", source_asset_id=source, target_asset_id=target)
    assert unknown_technique.status_code == 404
    unknown_asset = await evaluate(client, acme_id, technique_id="T1190", source_asset_id="missing", target_asset_id=target)
    assert unknown_asset.status_code == 404
    unknown_network = await evaluate(client, "missing", technique_id="T1190", source_asset_id=source, target_asset_id=target)
    assert unknown_network.status_code == 404

    missing_field = await evaluate(client, acme_id, technique_id="T1190", source_asset_id=source)
    assert missing_field.status_code == 422
    bad_port = await evaluate(
        client, acme_id, technique_id="T1190", source_asset_id=source, target_asset_id=target, port=0
    )
    assert bad_port.status_code == 422


async def test_unreachable_target_is_422(client: AsyncClient, acme_id: str, acme_codes: Codes) -> None:
    removed = await client.delete(f"{API}/networks/{acme_id}/assets/{acme_codes['AP-01']}")
    assert removed.status_code == 204
    response = await evaluate(
        client, acme_id,
        technique_id="T1190", source_asset_id=acme_codes["GUEST-DEV"], target_asset_id=acme_codes["DB-01"],
    )
    assert response.status_code == 422
    assert response.json()["error"]["message"] == "No path from GUEST-DEV to DB-01"

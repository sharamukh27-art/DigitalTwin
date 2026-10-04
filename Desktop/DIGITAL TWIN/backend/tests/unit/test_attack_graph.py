"""Attack graph: pivot edges, attack paths, choke points and the best cut."""

from typing import Any

import pytest

from app.analysis import attack_graph as ag
from app.controls import repository as control_repository
from app.controls.connectivity import check_flow
from app.core.errors import NotFound
from app.models.asset import Asset, Port
from app.models.control import SecurityControl, VlanRule
from app.remediation import service as remediation_service
from app.simulation import engine
from app.twin import graph as twin_graph
from app.twin.versioning import bump_version
from tests.sim import make_link
from tests.steps import make_control


@pytest.fixture(autouse=True)
def fresh_cache() -> None:
    ag.clear_cache()


def host(code: str, zone: str, criticality: int = 2, ports: tuple[int, ...] = (22,), asset_type: str = "server") -> Asset:
    return Asset(
        id=code, network_id="n", code=code, name=code, type=asset_type, zone=zone, criticality=criticality,
        open_ports=[Port(port=port, protocol="tcp", service="svc") for port in ports],
    )


def small(controls: list[SecurityControl] | None = None, **kwargs: Any) -> Any:
    """INTERNET can reach M and N; both can reach the critical target T. X is a dead end."""
    assets = [
        host("INTERNET", "internet", 1, (), "attacker_node"),
        host("M", "dmz"), host("N", "dmz"), host("X", "dmz"),
        host("T", "server", 5, (5432,), "database"),
    ]
    links = [make_link("L1", "INTERNET", "M"), make_link("L2", "INTERNET", "N"), make_link("L3", "INTERNET", "X"),
             make_link("L4", "M", "T"), make_link("L5", "N", "T")]
    topology = twin_graph.graph_from_models(assets, links)
    return ag.build_attack_graph("n", 1, assets, controls or [], topology, **kwargs)


def test_small_graph_counts_paths_and_shares() -> None:
    result = small(max_hops=2)
    assert (result.entries, result.targets, result.reachable_targets) == (["INTERNET"], ["T"], ["T"])
    assert [path.asset_codes for path in result.paths] == [
        ["INTERNET", "T"], ["INTERNET", "M", "T"], ["INTERNET", "N", "T"], ["INTERNET", "X", "T"],
    ]
    assert result.total_paths == 4 and result.truncated is False
    assert [(c.asset_code, c.paths_through, c.percent) for c in result.choke_points] == [("M", 1, 25.0), ("N", 1, 25.0), ("X", 1, 25.0)]
    assert result.paths[1].model_dump() == {
        "asset_codes": ["INTERNET", "M", "T"], "hops": 2, "entry_code": "INTERNET", "target_code": "T", "target_criticality": 5,
    }
    top = next(flow for flow in result.choke_flows if flow.target_code == "T" and flow.source_code == "INTERNET")
    assert result.choke_flows[0].source_code == "INTERNET" and len(result.choke_flows) == 7
    assert (top.source_code, top.target_code, top.paths_through, top.percent) == ("INTERNET", "T", 1, 25.0)
    assert top.ports[0].model_dump(mode="json") == {"port": 5432, "protocol": "tcp", "service": "svc", "allowed_by": None, "rule_index": None}


def test_unfiltered_cable_reach_is_what_makes_x_a_pivot() -> None:
    # X has no cable to T, but nothing filters X -> INTERNET -> ... so reachability follows the cables through other nodes.
    result = small(max_hops=1)
    assert [path.asset_codes for path in result.paths] == [["INTERNET", "T"]]
    assert result.choke_points == [] and result.best_cut.host is None


def test_a_firewall_removes_pivot_edges() -> None:
    target = host("T", "server", 5, (5432,), "database")
    deny_dmz = make_control(
        "FW", "firewall", "inline",
        {"rules": [{"src_zone": "internet", "dst_zone": "server", "action": "deny"}, {"src_zone": "dmz", "dst_zone": "server", "ports": [5432], "action": "allow"}],
         "default_action": "deny", "logging": False},
        assets=[target],
    )
    result = small([deny_dmz], max_hops=2)
    assert ["INTERNET", "T"] not in [path.asset_codes for path in result.paths]
    assert result.total_paths == 3
    flow = next(item for item in result.choke_flows if item.source_code == "M")
    assert (flow.ports[0].allowed_by, flow.ports[0].rule_index) == ("FW", 1)

    closed = make_control("FW", "firewall", "inline", {"rules": [], "default_action": "deny", "logging": False}, assets=[target])
    nothing = small([closed])
    assert (nothing.total_paths, nothing.reachable_targets, nothing.paths) == (0, [], [])
    assert nothing.best_cut.model_dump() == {
        "host": None, "flow": None, "host_suggestion": None, "flow_suggestion": None, "related_remediations": [],
    }
    assert all(point.percent == 0.0 for point in nothing.choke_points)


def test_criticality_threshold_and_truncation(monkeypatch: pytest.MonkeyPatch) -> None:
    assert small(min_criticality=5).targets == ["T"]
    assert small(min_criticality=2).targets == ["M", "N", "T", "X"]
    monkeypatch.setattr(ag, "PATH_CAP", 2)
    capped = small(max_hops=2)
    assert (capped.total_paths, capped.truncated) == (2, True)


def test_check_flow(acme_assets: dict[str, Asset], acme_controls: dict[str, SecurityControl]) -> None:
    controls = list(acme_controls.values())
    ids = lambda *codes: [acme_assets[code].id for code in codes]  # noqa: E731
    web = check_flow(controls, acme_assets["INTERNET"], acme_assets["WEB-01"], ids("INTERNET", "FW-EDGE", "WEB-01"), "tcp", 443)
    assert (web.allowed, web.rule_index) == (True, 0)
    db = check_flow(controls, acme_assets["INTERNET"], acme_assets["DB-01"], ids("INTERNET", "FW-EDGE", "FW-INT", "SW-CORE", "DB-01"), "tcp", 5432)
    assert db.allowed is False


async def test_sample_network(acme_id: str) -> None:
    result = await ag.attack_graph(acme_id)
    assert (result.network_id, result.network_version, result.min_criticality, result.max_hops) == (acme_id, 1, 4, 4)
    assert result.entries == ["GUEST-DEV", "INTERNET"]
    assert result.targets == ["ADMIN-01", "APP-01", "DB-01", "DC-01", "FS-01", "VPN-01"]
    assert result.reachable_targets == ["APP-01", "DB-01", "DC-01", "FS-01", "VPN-01"]
    assert (result.total_paths, result.truncated, result.pivot_edge_count) == (223, False, 187)
    assert len(result.paths) == 50
    assert result.paths[0].asset_codes == ["INTERNET", "VPN-01"]
    assert ["INTERNET", "WEB-01", "APP-01"] in [path.asset_codes for path in result.paths]
    assert all(path.hops <= 4 for path in result.paths)
    assert [path.hops for path in result.paths] == sorted(path.hops for path in result.paths)

    top = result.choke_points[0]
    assert (top.asset_code, top.paths_through, top.percent, top.zone.value, top.is_target) == ("SW-ACCESS-2", 192, 86.1, "corporate", False)
    assert result.choke_points[1].asset_code == "APP-01" and result.choke_points[1].is_target is True
    assert [p.paths_through for p in result.choke_points] == sorted((p.paths_through for p in result.choke_points), reverse=True)

    cut = result.best_cut
    assert cut.host == top
    assert (cut.flow.source_code, cut.flow.target_code, cut.flow.paths_through) == ("GUEST-DEV", "SW-ACCESS-2", 192)
    assert cut.flow.ports[0].model_dump(mode="json") == {"port": 22, "protocol": "tcp", "service": "ssh", "allowed_by": "SEG-01", "rule_index": None}
    assert cut.flow_suggestion == (
        "192 of the attack paths (86.1%) use GUEST-DEV -> SW-ACCESS-2 on port 22; "
        "the default action of SEG-01 allows it. Blocking that flow cuts them."
    )
    assert cut.host_suggestion.startswith("192 of the attack paths (86.1%) pass through SW-ACCESS-2.")
    assert cut.related_remediations == []


async def test_fewer_hops_and_higher_criticality(acme_id: str) -> None:
    short = await ag.attack_graph(acme_id, max_hops=3)
    assert short.total_paths == 43
    crown = await ag.attack_graph(acme_id, min_criticality=5)
    assert crown.targets == ["DB-01", "DC-01"]
    assert crown.total_paths < 223


async def test_closing_the_top_flow_removes_its_paths_and_refreshes_with_the_version(acme_id: str) -> None:
    before = await ag.attack_graph(acme_id)
    assert await ag.attack_graph(acme_id) == before

    seg = next(c for c in await control_repository.all_controls(acme_id) if c.code == "SEG-01")
    rules = [VlanRule(src_vlan=50, dst_vlan=99, action="deny"), *seg.config.vlan_rules]
    await control_repository.replace_control(seg.model_copy(update={"config": seg.config.model_copy(update={"vlan_rules": rules})}))
    assert (await ag.attack_graph(acme_id)).total_paths == 223  # still the cached version 1

    await bump_version(acme_id)
    after = await ag.attack_graph(acme_id)
    assert after.network_version == 2
    assert after.total_paths == 223 - 192
    assert all(path.entry_code == "INTERNET" for path in after.paths)
    assert after.best_cut.host.asset_code == "APP-01"
    assert {key[1] for key in ag._CACHE if key[0] == acme_id} == {2}


async def test_related_remediations_point_at_the_best_cut_host(acme_id: str) -> None:
    run = await engine.run(acme_id, "S1")
    await remediation_service.generate_for_run(run.id)
    related = (await ag.attack_graph(acme_id)).best_cut.related_remediations
    titles = {item.title for item in related}
    assert {"Enable dynamic ARP inspection on SWSEC-2", "Disable MAC authentication bypass on NAC-01"} <= titles
    assert all(item.status.value == "proposed" for item in related)


async def test_unknown_network(database: Any) -> None:
    with pytest.raises(NotFound):
        await ag.attack_graph("missing")

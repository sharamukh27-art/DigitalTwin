"""Helpers for simulation tests: load a twin into memory, tweak controls, build scenarios."""

from dataclasses import dataclass
from typing import Any

import networkx as nx

from app.controls import repository as control_repository
from app.models.asset import Asset
from app.models.control import SecurityControl
from app.models.link import Link
from app.models.run import SimulationOutcome
from app.models.scenario import Scenario
from app.scenarios import catalog
from app.simulation import engine
from app.twin import graph as twin_graph
from app.twin import repository


@dataclass
class World:
    """A twin held in memory for calling the pure engine."""

    assets: list[Asset]
    links: list[Link]
    controls: list[SecurityControl]
    graph: nx.MultiDiGraph

    def run(self, scenario: Scenario | str, seed: int = 42, controls: list[SecurityControl] | None = None) -> SimulationOutcome:
        chosen = catalog.get(scenario) if isinstance(scenario, str) else scenario
        return engine.simulate(
            chosen, self.assets, self.links, self.controls if controls is None else controls, self.graph, seed
        )

    def asset(self, code: str) -> Asset:
        return next(asset for asset in self.assets if asset.code == code)

    def with_control(
        self,
        code: str,
        config: dict[str, Any] | None = None,
        services: list[str] | None = None,
        asset_codes: list[str] | None = None,
        enabled: bool | None = None,
    ) -> list[SecurityControl]:
        """Return the controls with one of them changed."""
        changed: list[SecurityControl] = []
        for control in self.controls:
            if control.code == code:
                update: dict[str, Any] = {}
                if config is not None:
                    merged = {**control.config.model_dump(mode="json"), **config}
                    update["config"] = type(control.config).model_validate(merged)
                placement: dict[str, Any] = {}
                if services is not None:
                    placement["services"] = services
                if asset_codes is not None:
                    placement["asset_ids"] = [self.asset(item).id for item in asset_codes]
                if placement:
                    update["placement"] = control.placement.model_copy(update=placement)
                if enabled is not None:
                    update["enabled"] = enabled
                control = control.model_copy(update=update)
            changed.append(control)
        return changed


async def load_world(network_id: str) -> World:
    """Load a stored network into memory."""
    return World(
        assets=await repository.all_assets(network_id),
        links=await repository.all_links(network_id),
        controls=await control_repository.all_controls(network_id),
        graph=await twin_graph.build_graph(network_id),
    )


def make_world(
    assets: list[Asset], links: list[Link], controls: list[SecurityControl] | None = None
) -> World:
    """Build a small in-memory twin."""
    return World(assets=assets, links=links, controls=controls or [], graph=twin_graph.graph_from_models(assets, links))


def make_asset(code: str, asset_type: str = "server", zone: str = "server", criticality: int = 3, vlan: int | None = None) -> Asset:
    return Asset(id=code, network_id="n", code=code, name=code, type=asset_type, zone=zone, criticality=criticality, vlan=vlan)


def make_link(code: str, source: str, target: str) -> Link:
    return Link(id=code, network_id="n", code=code, source_asset_id=source, target_asset_id=target, type="ethernet")


def step(order: int, technique_id: str = "T1190", **fields: Any) -> dict[str, Any]:
    """Build a step dict. Tactic and layer are filled from the technique catalog."""
    from app.twin import techniques

    technique = techniques.get(technique_id)
    data: dict[str, Any] = {
        "order": order,
        "name": f"step {order}",
        "technique_id": technique_id,
        "tactic": technique.tactic.value,
        "layer": technique.osi_layer,
    }
    data.update(fields)
    return data


def make_scenario(steps: list[dict[str, Any]], entry: str = "A", goal: dict[str, Any] | None = None, **fields: Any) -> Scenario:
    data: dict[str, Any] = {
        "id": "00000000-0000-4000-8000-000000000001",
        "code": "T1",
        "name": "test scenario",
        "description": "test",
        "attacker_profile": "outsider",
        "entry": {"asset_code": entry},
        "goal": goal or {"kind": "reach_asset", "target_code": "B"},
        "steps": steps,
    }
    data.update(fields)
    return Scenario.model_validate(data)

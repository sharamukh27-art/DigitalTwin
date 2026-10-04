"""Patch operations and the deterministic remediation rules."""

from typing import Any

import pytest
from pydantic import ValidationError

from app.analysis import service, whatif
from app.controls import catalog
from app.controls import repository as control_repository
from app.core.errors import Conflict, ValidationFailed
from app.models.enums import ControlType
from app.models.remediation import Candidate
from app.models.whatif import PatchOp
from app.remediation import rules, snippets
from app.simulation import engine
from app.twin import repository
from tests.steps import make_control


def op(code: str, **fields: Any) -> PatchOp:
    return PatchOp(target="control", code=code, **fields)


async def candidates_for(network_id: str, scenario: str) -> dict[str, Candidate]:
    run = await engine.run(network_id, scenario)
    findings = await service.findings_for(run)
    twin = await service.load_twin(network_id)
    return {item.template_title: item for item in rules.generate_candidates(run, findings, twin)}


def ops_of(candidate: Candidate) -> list[dict[str, Any]]:
    return [
        {key: value for key, value in item.model_dump(mode="json").items() if value and key != "target"}
        for item in candidate.patch
    ]


def test_patch_op_needs_exactly_one_kind_of_change() -> None:
    assert op("X", set={"enabled": False}).append == {}
    assert op("X", append={"placement.zones": "dmz"}).set == {}
    assert op("X", create={"name": "n", "type": "edr"}).create is not None
    with pytest.raises(ValidationError, match="at least one of set, append, prepend or create"):
        op("X")
    with pytest.raises(ValidationError, match="create cannot be combined"):
        op("X", create={"name": "n"}, set={"enabled": True})
    with pytest.raises(ValidationError, match="create is only supported for controls"):
        PatchOp(target="asset", code="X", create={"name": "n"})


async def test_append_ops_combine_and_are_idempotent(acme_id: str) -> None:
    sandbox = await whatif.clone_to_sandbox(acme_id)
    patch = [
        op("EDR-01", append={"placement.asset_codes": "FS-01"}),
        op("EDR-01", append={"placement.asset_codes": "DB-01"}),
        op("EDR-01", append={"placement.asset_codes": "FS-01"}),
        op("MFA-01", append={"placement.services": "vpn", "config.enforced_for": "vpn"}),
        op("IDS-01", set={"config.mode": "ips"}, append={"config.signature_sets": "arp", "placement.zones": "corporate"}),
    ]
    assert await whatif.apply_patch(sandbox.id, patch) == 2

    controls = {c.code: c for c in await control_repository.all_controls(sandbox.id)}
    assets = {a.code: a.id for a in await repository.all_assets(sandbox.id)}
    edr = controls["EDR-01"].placement.asset_ids
    assert len(edr) == 14 and edr[-2:] == [assets["FS-01"], assets["DB-01"]]
    assert controls["MFA-01"].placement.services == ["email", "ad", "vpn"]
    assert controls["MFA-01"].config.enforced_for == ["email", "ad", "vpn"]
    ids = controls["IDS-01"]
    assert (ids.config.mode.value, [s.value for s in ids.config.signature_sets]) == ("ips", ["network", "web", "smb", "arp"])
    assert [zone.value for zone in ids.placement.zones] == ["dmz", "server", "corporate"]


async def test_prepend_puts_a_firewall_rule_first(acme_id: str) -> None:
    sandbox = await whatif.clone_to_sandbox(acme_id)
    deny = {"src_zone": "server", "dst_zone": "server", "ports": [5432], "protocol": "tcp", "action": "deny"}
    await whatif.apply_patch(sandbox.id, [op("FW-INT", prepend={"config.rules": deny})])
    firewall = next(c for c in await control_repository.all_controls(sandbox.id) if c.code == "FW-INT")
    assert len(firewall.config.rules) == 6
    assert firewall.config.rules[0].model_dump(mode="json") == deny
    assert firewall.config.rules[1].src_zone.value == "corporate"

    await whatif.apply_patch(sandbox.id, [op("FW-INT", prepend={"config.rules": deny})])
    again = next(c for c in await control_repository.all_controls(sandbox.id) if c.code == "FW-INT")
    assert len(again.config.rules) == 6


async def test_create_adds_a_control(acme_id: str) -> None:
    sandbox = await whatif.clone_to_sandbox(acme_id)
    body = {
        "name": "Data loss prevention", "type": "dlp",
        "placement": {"kind": "host", "asset_codes": ["FS-01"]},
        "config": {"mode": "block", "monitored_channels": ["web"]},
    }
    await whatif.apply_patch(sandbox.id, [op("DLP-01", create=body), op("DLP-01", append={"placement.asset_codes": "DB-01"})])

    controls = {c.code: c for c in await control_repository.all_controls(sandbox.id)}
    assets = {a.code: a.id for a in await repository.all_assets(sandbox.id)}
    assert len(controls) == 15
    created = controls["DLP-01"]
    assert (created.type, created.network_id, created.enabled) == (ControlType.DLP, sandbox.id, True)
    assert created.placement.asset_ids == [assets["FS-01"], assets["DB-01"]]
    assert len(await control_repository.all_controls(acme_id)) == 14


async def test_bad_append_prepend_and_create_are_rejected(acme_id: str) -> None:
    sandbox = await whatif.clone_to_sandbox(acme_id)
    bad = [
        op("EDR-01", append={"config.mode": "x"}),
        op("EDR-01", append={"placement.asset_codes": "GHOST"}),
        op("EDR-01", append={"placement.zones": "moon"}),
        op("EDR-01", prepend={"config.rules": {}}),
        op("WAF-01", create={"name": "dup", "type": "waf", "placement": {"kind": "network_wide"}, "config": {"mode": "block"}}),
        op("NEW-1", create={"name": "bad", "type": "edr", "placement": {"kind": "network_wide"}, "config": {"mode": "maybe"}}),
        op("NEW-2", create={"name": "bad", "type": "edr", "placement": {"kind": "host", "asset_codes": ["GHOST"]}, "config": {"mode": "block"}}),
        op("NEW-3", create={"name": "bad", "type": "edr", "placement": {"kind": "host"}, "config": {"mode": "block"}}),
    ]
    with pytest.raises(ValidationFailed) as caught:
        await whatif.apply_patch(sandbox.id, bad)
    joined = "\n".join(caught.value.details["errors"])
    for expected in (
        "patch[0] (control EDR-01): 'config.mode' is not a list",
        "patch[1] (control EDR-01): 'placement.asset_codes': no asset with code GHOST",
        "patch[2] (control EDR-01): placement.zones.0: Input should be",
        "patch[3] (control EDR-01): unknown path 'config.rules'",
        "patch[4] (control WAF-01): a control with code WAF-01 already exists",
        "patch[5] (control NEW-1): Value error, config.mode",
        "patch[6] (control NEW-2): placement.asset_codes must be a list of asset codes",
        "patch[7] (control NEW-3): host placement needs at least one asset",
    ):
        assert expected in joined
    assert len(caught.value.details["errors"]) == 8
    assert len(await control_repository.all_controls(sandbox.id)) == 14


async def test_real_networks_are_only_patched_through_the_explicit_path(acme_id: str) -> None:
    fix = [op("SWSEC-2", set={"config.dynamic_arp_inspection": True})]
    with pytest.raises(Conflict):
        await whatif.prepare_patch(acme_id, fix)
    prepared = await whatif.prepare_patch(acme_id, fix, require_sandbox=False)
    assert [c.code for c in prepared[1]] == ["SWSEC-2"] and prepared[0] == [] and prepared[2] == []
    assert (await repository.get_network(acme_id)).version == 1


def test_requirement_ops() -> None:
    switch = make_control(
        "SW", "switch_security", "inline",
        {"port_security": True, "max_macs_per_port": 2, "dhcp_snooping": False, "dynamic_arp_inspection": False},
    )
    capability = catalog.get_capability(ControlType.SWITCH_SECURITY, "T1557.002")
    ops, changes = rules.requirement_ops(switch, capability)
    assert [o.set for o in ops] == [{"config.dynamic_arp_inspection": True, "config.dhcp_snooping": True}]
    assert changes == [("dynamic_arp_inspection", True), ("dhcp_snooping", True)]

    ids = make_control("IDS", "ids_ips", "sensor", {"mode": "ids", "signature_sets": ["web"]}, zones=["dmz"])
    ops, changes = rules.requirement_ops(ids, catalog.get_capability(ControlType.IDS_IPS, "T1110"))
    assert [o.append for o in ops] == [{"config.signature_sets": "auth"}] and changes == [("signature_sets", "auth")]

    policy = make_control("IDP", "identity_policy", "identity", {"lockout_threshold": None, "password_min_length": 8}, services=["vpn"])
    ops, _ = rules.requirement_ops(policy, catalog.get_capability(ControlType.IDENTITY_POLICY, "T1110"))
    assert [o.set for o in ops] == [{"config.lockout_threshold": 5}]

    fine = make_control("OK", "identity_policy", "identity", {"lockout_threshold": 3, "password_min_length": 8}, services=["vpn"])
    assert rules.requirement_ops(fine, catalog.get_capability(ControlType.IDENTITY_POLICY, "T1110")) == ([], [])


def test_fingerprint_is_stable_and_sensitive() -> None:
    first = [op("A", set={"enabled": False})]
    assert rules.fingerprint(first) == rules.fingerprint([op("A", set={"enabled": False})])
    assert rules.fingerprint(first) != rules.fingerprint([op("A", set={"enabled": True})])
    assert len(rules.fingerprint(first)) == 64


async def test_s1_gaps_dai_and_mac_auth_bypass(acme_id: str) -> None:
    found = await candidates_for(acme_id, "S1")
    assert list(found) == [
        "Enable dynamic ARP inspection on SWSEC-2",
        "Extend IDS-01 to the corporate zone",
        "Disable MAC authentication bypass on NAC-01",
        "Deny VLAN 10 to VLAN 20 at SEG-01",
        "Switch IDS-01 from ids to ips mode",
        "Put APP-01 behind WAF-01",
        "Enable user behaviour analytics on SIEM-01",
        "Protect the database service with MFA-01",
        "Deny server to server on port 5432 at FW-INT",
    ]
    dai = found["Enable dynamic ARP inspection on SWSEC-2"]
    assert ops_of(dai) == [{"code": "SWSEC-2", "set": {"config.dynamic_arp_inspection": True}}]
    assert (dai.rule.value, dai.effort.value, dai.technique_id, dai.step_order) == ("missed_requirement", "low", "T1557.002", 1)
    assert dai.config_snippet == "ip arp inspection vlan 10,50"
    assert dai.affected_assets == ["SW-ACCESS-2"]
    assert dai.template_rationale == (
        "In scenario S1 step 1, T1557.002 ARP Cache Poisoning against SW-ACCESS-2 was missed by SWSEC-2: "
        "dynamic_arp_inspection is false on SWSEC-2. With this change SWSEC-2 can block it."
    )
    assert dai.caveats == []

    nac = found["Disable MAC authentication bypass on NAC-01"]
    assert ops_of(nac) == [{"code": "NAC-01", "set": {"config.mac_auth_bypass_allowed": False}}]
    assert nac.config_snippet.startswith("no mab\n# require 802.1X")
    assert nac.affected_assets == ["AP-01", "SW-ACCESS-1", "SW-ACCESS-2"]

    siem = found["Enable user behaviour analytics on SIEM-01"]
    assert ops_of(siem) == [{"code": "SIEM-01", "set": {"config.ueba": True}}]
    assert siem.affected_assets == ["network-wide"] and "UEBA" in siem.config_snippet
    assert "With this change SIEM-01 can detect it." in siem.template_rationale


async def test_dai_fix_also_enables_dhcp_snooping_when_it_is_off(acme_id: str) -> None:
    swsec = next(c for c in await control_repository.all_controls(acme_id) if c.code == "SWSEC-2")
    weaker = swsec.model_copy(update={"config": swsec.config.model_copy(update={"dhcp_snooping": False})})
    await control_repository.replace_control(weaker)

    found = await candidates_for(acme_id, "S1")
    both = found["Enable dynamic ARP inspection on SWSEC-2 (and 1 related setting)"]
    assert ops_of(both) == [
        {"code": "SWSEC-2", "set": {"config.dynamic_arp_inspection": True, "config.dhcp_snooping": True}}
    ]
    assert both.config_snippet == "ip arp inspection vlan 10,50\nip dhcp snooping\nip dhcp snooping vlan 10,50"


async def test_s3_gap_waf_in_detect_mode(acme_id: str) -> None:
    found = await candidates_for(acme_id, "S3")
    waf = found["Switch WAF-01 from detect to block mode"]
    assert ops_of(waf) == [{"code": "WAF-01", "set": {"config.mode": "block"}}]
    assert (waf.rule.value, waf.effort.value, waf.affected_assets) == ("mode_downgrade", "medium", ["WEB-01"])
    assert waf.config_snippet.startswith("set WAF mode: prevention (block)")
    assert "runs in detect mode" in waf.template_rationale

    ids = found["Switch IDS-01 from ids to ips mode"]
    assert ops_of(ids) == [{"code": "IDS-01", "set": {"config.mode": "ips"}}]
    assert ids.affected_assets == ["zone dmz", "zone server"]

    blind = found["Deploy EDR-01 to DB-01"]
    assert ops_of(blind) == [{"code": "EDR-01", "append": {"placement.asset_codes": "DB-01"}}]
    assert (blind.rule.value, blind.technique_id, blind.step_order, blind.affected_assets) == ("placement_gap", "T1005", 5, ["DB-01"])


async def test_s4_gaps_mfa_without_vpn_and_no_lockout(acme_id: str) -> None:
    found = await candidates_for(acme_id, "S4")
    assert list(found) == [
        "Protect the vpn service with MFA-01",
        "Set an account lockout threshold on IDP-01",
        "Load auth signatures on IDS-01",
        "Enable user behaviour analytics on SIEM-01",
    ]
    mfa = found["Protect the vpn service with MFA-01"]
    assert ops_of(mfa) == [{"code": "MFA-01", "append": {"placement.services": "vpn", "config.enforced_for": "vpn"}}]
    assert mfa.config_snippet == "require mfa for service: vpn"
    assert mfa.affected_assets == ["service email", "service ad"]

    lockout = found["Set an account lockout threshold on IDP-01"]
    assert ops_of(lockout) == [{"code": "IDP-01", "set": {"config.lockout_threshold": 5}}]
    assert lockout.config_snippet == "account lockout threshold: 5 failed attempts\nlockout duration: 15 minutes"
    assert lockout.effort.value == "low"

    signatures = found["Load auth signatures on IDS-01"]
    assert ops_of(signatures) == [{"code": "IDS-01", "append": {"config.signature_sets": "auth"}}]


async def test_s5_gaps_edr_missing_on_file_server_and_no_offline_backup(acme_id: str) -> None:
    found = await candidates_for(acme_id, "S5")
    edr = found["Deploy EDR-01 to FS-01"]
    assert ops_of(edr) == [{"code": "EDR-01", "append": {"placement.asset_codes": "FS-01"}}]
    assert edr.config_snippet == "install the edr agent on FS-01\nassign it to the EDR-01 policy"
    assert edr.affected_assets == ["FS-01"]

    backup = found["Keep an offline backup copy for FS-01"]
    assert ops_of(backup) == [{"code": "BKP-01", "set": {"config.offline_copies": True}}]
    assert (backup.rule.value, backup.technique_id, backup.affected_assets) == ("offline_backup", "T1486", ["DB-01", "FS-01"])
    assert "offline or immutable backup copy for: DB-01, FS-01" in backup.config_snippet
    assert "does not stop the attack" in backup.template_rationale


async def test_s6_blind_spot_and_connectivity_holes(acme_id: str) -> None:
    found = await candidates_for(acme_id, "S6")

    sensor = found["Extend IDS-01 to the management zone"]
    assert ops_of(sensor) == [{"code": "IDS-01", "append": {"placement.zones": "management"}}]

    dlp = found["Add a data loss prevention control to block Exfiltration Over Alternative Protocol"]
    assert ops_of(dlp) == [
        {
            "code": "DLP-01",
            "create": {
                "name": "Data loss prevention", "type": "dlp", "enabled": True,
                "placement": {"kind": "network_wide"},
                "config": {"mode": "block", "monitored_channels": ["web", "email"]},
            },
        }
    ]
    assert (dlp.rule.value, dlp.effort.value, dlp.caveats) == ("new_control", "high", [snippets.NEW_CONTROL_CAVEAT])

    edge = found["Deny management to internet on port 443 at FW-EDGE"]
    assert ops_of(edge) == [
        {
            "code": "FW-EDGE",
            "prepend": {"config.rules": {"src_zone": "management", "dst_zone": "internet", "ports": [443], "protocol": "tcp", "action": "deny"}},
        }
    ]
    assert edge.config_snippet == "deny tcp from zone management to zone internet port 443\n# place before rule 2 on FW-EDGE"
    assert (edge.rule.value, edge.effort.value, edge.caveats) == ("connectivity_hole", "high", [snippets.CONNECTIVITY_CAVEAT])
    assert "a broad rule that does not limit zones" in edge.template_rationale

    vlan = found["Deny VLAN 99 to VLAN 20 at SEG-01"]
    assert ops_of(vlan) == [{"code": "SEG-01", "prepend": {"config.vlan_rules": {"src_vlan": 99, "dst_vlan": 20, "action": "deny"}}}]
    assert "allows by default" in vlan.template_rationale
    assert "Deny management to server on port 445 at FW-INT" in found


async def test_no_candidates_when_nothing_failed_or_gaps_are_already_closed(acme_id: str) -> None:
    assert await candidates_for(acme_id, "S2") == {}

    run = await engine.run(acme_id, "S4")
    findings = await service.findings_for(run)
    mfa = next(c for c in await control_repository.all_controls(acme_id) if c.code == "MFA-01")
    covered = ["email", "ad", "vpn"]
    await control_repository.replace_control(
        mfa.model_copy(
            update={
                "config": mfa.config.model_copy(update={"enforced_for": covered}),
                "placement": mfa.placement.model_copy(update={"services": covered}),
            }
        )
    )
    twin = await service.load_twin(acme_id)
    titles = [item.template_title for item in rules.generate_candidates(run, findings, twin)]
    assert "Protect the vpn service with MFA-01" not in titles
    assert "Set an account lockout threshold on IDP-01" in titles


async def test_every_candidate_patch_applies_cleanly_in_a_sandbox(acme_id: str) -> None:
    total = 0
    for scenario in ("S1", "S3", "S4", "S5", "S6"):
        for candidate in (await candidates_for(acme_id, scenario)).values():
            sandbox = await whatif.clone_to_sandbox(acme_id)
            assert await whatif.apply_patch(sandbox.id, candidate.patch) == 2
            await whatif.delete_sandbox(sandbox.id)
            assert candidate.config_snippet and candidate.template_title and candidate.template_rationale
            total += 1
    assert total == 31

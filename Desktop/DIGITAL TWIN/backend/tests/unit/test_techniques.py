"""ATT&CK technique catalog."""

import pytest

from app.core.errors import NotFound
from app.models.enums import Tactic
from app.twin import techniques

EXPECTED = {
    "T1557.002": ("ARP Cache Poisoning", "credential_access", 2),
    "T1599": ("Network Boundary Bridging", "defense_evasion", 3),
    "T1566.001": ("Spearphishing Attachment", "initial_access", 7),
    "T1078": ("Valid Accounts", "initial_access", 7),
    "T1021.002": ("SMB/Windows Admin Shares", "lateral_movement", 7),
    "T1190": ("Exploit Public-Facing Application", "initial_access", 7),
    "T1505.003": ("Web Shell", "persistence", 7),
    "T1110": ("Brute Force", "credential_access", 7),
    "T1133": ("External Remote Services", "initial_access", 7),
    "T1486": ("Data Encrypted for Impact", "impact", 7),
    "T1005": ("Data from Local System", "collection", 7),
    "T1048": ("Exfiltration Over Alternative Protocol", "exfiltration", 4),
    "T1046": ("Network Service Discovery", "discovery", 4),
    "T1003": ("OS Credential Dumping", "credential_access", 7),
}


def test_catalog_matches_specification() -> None:
    catalog = {technique.id: technique for technique in techniques.all()}
    assert set(catalog) == set(EXPECTED)
    for technique_id, (name, tactic, layer) in EXPECTED.items():
        technique = catalog[technique_id]
        assert (technique.name, technique.tactic.value, technique.osi_layer) == (name, tactic, layer)
        assert technique.description


def test_get_returns_technique() -> None:
    assert techniques.get("T1190").name == "Exploit Public-Facing Application"


def test_get_unknown_id_raises_not_found() -> None:
    with pytest.raises(NotFound):
        techniques.get("T9999")


def test_by_tactic_accepts_enum_and_string() -> None:
    expected = {"T1566.001", "T1078", "T1190", "T1133"}
    assert {technique.id for technique in techniques.by_tactic("initial_access")} == expected
    assert {technique.id for technique in techniques.by_tactic(Tactic.INITIAL_ACCESS)} == expected


def test_by_tactic_with_no_techniques_is_empty() -> None:
    assert techniques.by_tactic(Tactic.RECONNAISSANCE) == []

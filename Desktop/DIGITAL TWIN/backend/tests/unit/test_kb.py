"""Knowledge base: source parsers, chunking, ingest and retrieval on a tiny fixture index."""

import json
from pathlib import Path

import pytest

from app.core.config import get_settings
from app.models.enums import SourceKind
from app.rag import sources
from app.rag.chunking import chunk_document, estimate_tokens
from app.rag.documents import Document, IngestSummary
from app.rag.embedding import HashEmbedder, tokenize
from app.rag.ingest import build_index, load_documents
from app.rag.retrieve import bm25_rank, reciprocal_rank_fusion, retrieve
from app.rag.store import KnowledgeStore
from tests.conftest import KB_FIXTURES


def load(name: str) -> dict:
    return json.loads((KB_FIXTURES / name).read_text())


def test_clean_text() -> None:
    raw = "Uses [Network Sniffing](https://attack.mitre.org/techniques/T1040).(Citation: X 2020)  <code>arp -a</code>"
    assert sources.clean_text(raw) == "Uses Network Sniffing. arp -a"


def test_parse_attack() -> None:
    documents = sources.parse_attack(load("enterprise-attack.json"))
    assert [document.section_id for document in documents] == ["T1110", "T1190", "T1557.002"]

    arp = documents[2]
    assert (arp.id, arp.kind, arp.source_name) == ("attack:T1557.002", SourceKind.ATTACK, "MITRE ATT&CK")
    assert arp.source_url == "https://attack.mitre.org/techniques/T1557/002"
    assert arp.technique_ids == ["T1557.002"]
    assert arp.text.startswith("T1557.002 ARP Cache Poisoning\n\nAdversaries may poison")
    assert "Citation" not in arp.text and "https://" not in arp.text and "Network Sniffing" in arp.text
    assert (
        "Detection:\n- Detect ARP Cache Poisoning: Detects anomalous ARP traffic such as multiple IP "
        "addresses resolving to a single MAC address."
    ) in arp.text
    assert (
        "Mitigations:\n- M1031 Network Intrusion Prevention: Network intrusion prevention systems can "
        "identify traffic patterns indicative of ARP poisoning."
    ) in arp.text

    web = documents[1]
    assert "Detection:\n- Monitor application logs" in web.text
    assert "Mitigations" not in web.text
    brute = documents[0]
    assert "- M1032 Multi-factor Authentication: Use two or more pieces of evidence" in brute.text
    assert "Detection" not in brute.text


def test_parse_d3fend_maps_defenses_to_attack_techniques_through_artifacts() -> None:
    documents = {document.section_id: document for document in sources.parse_d3fend(load("d3fend.json"))}
    assert sorted(documents) == ["D3-FE", "D3-NTA", "D3-SPP"]

    traffic = documents["D3-NTA"]
    assert traffic.technique_ids == ["T1557", "T1557.002"]
    assert traffic.text.startswith("D3-NTA Network Traffic Analysis\n\nAnalyzing intercepted")
    assert "duplicate" not in traffic.text
    assert "Sensors inspect ARP replies" in traffic.text and "##" not in traffic.text
    assert "Acts on: NetworkTraffic" in traffic.text
    assert traffic.source_url == "https://d3fend.mitre.org/technique/d3f:NetworkTrafficAnalysis"
    assert (traffic.kind, traffic.source_name) == (SourceKind.D3FEND, "MITRE D3FEND")

    assert documents["D3-FE"].technique_ids == ["T1486"]
    assert documents["D3-SPP"].technique_ids == []


def test_parse_nist() -> None:
    documents = sources.parse_nist(load("NIST_SP-800-53_rev5_catalog.json"))
    assert [document.section_id for document in documents] == ["AC-7", "AC-7(2)", "SC-7"]

    lockout = documents[0]
    assert lockout.text == (
        "AC-7 Unsuccessful Logon Attempts\n\n"
        "a. Enforce a limit of [number] consecutive invalid logon attempts by a user during a [time period];\n"
        "b. Automatically lock the account when the maximum number of unsuccessful attempts is exceeded."
    )
    assert (lockout.control_family, lockout.kind, lockout.technique_ids) == ("Access Control", SourceKind.NIST, [])
    assert "Guidance" not in lockout.text
    assert "after [number] unsuccessful" in documents[1].text
    assert documents[2].control_family == "System and Communications Protection"


def test_parse_policy(tmp_path: Path) -> None:
    path = tmp_path / "wifi_policy.md"
    path.write_text("# Wi-Fi Policy\n\nIntro.\n\n## Guest access\n\nGuests are isolated to stop T1599 and T1557.002.\n\n## Empty\n\n## Keys\n\nRotate keys yearly.\n")
    documents = sources.parse_policy(path)
    assert [document.section_id for document in documents] == ["wifi_policy#guest-access", "wifi_policy#keys"]
    guest = documents[0]
    assert guest.text == "Wi-Fi Policy: Guest access\n\nGuests are isolated to stop T1599 and T1557.002."
    assert guest.technique_ids == ["T1557.002", "T1599"]
    assert guest.source_name == "Organisation policy: Wi-Fi Policy"
    assert guest.source_url == "org-policy://wifi_policy.md#guest-access"
    assert documents[1].technique_ids == []


def test_shipped_sample_policies() -> None:
    files = sorted(get_settings().kb_policies_dir.glob("*.md"))
    assert [path.name for path in files] == ["network_access_policy.md", "remote_access_policy.md"]
    documents = [document for path in files for document in sources.parse_policy(path)]
    assert len(documents) == 9
    assert any("T1557.002" in document.technique_ids for document in documents)
    assert any("T1133" in document.technique_ids for document in documents)


def make_document(words: int) -> Document:
    return Document(
        id="doc", text=" ".join(f"w{index}" for index in range(words)), source_name="S", source_url="u",
        section_id="sec", technique_ids=["T1190"], control_family="F", kind="nist",
    )


def test_short_document_is_one_chunk() -> None:
    (chunk,) = chunk_document(make_document(100), max_tokens=220, overlap_tokens=40)
    assert (chunk.id, chunk.document_id, chunk.chunk_index) == ("doc::0", "doc", 0)
    assert (chunk.section_id, chunk.technique_ids, chunk.control_family) == ("sec", ["T1190"], "F")
    assert estimate_tokens(chunk.text) == 133


def test_long_document_is_split_with_overlap_and_keeps_metadata() -> None:
    chunks = chunk_document(make_document(400), max_tokens=220, overlap_tokens=40)
    assert [chunk.id for chunk in chunks] == ["doc::0", "doc::1", "doc::2"]
    assert all(estimate_tokens(chunk.text) <= 220 for chunk in chunks)
    first, second, third = (chunk.text.split() for chunk in chunks)
    assert (first[0], first[-1], len(first)) == ("w0", "w164", 165)
    assert second[:30] == first[-30:]
    assert third[-1] == "w399"
    assert {word for chunk in chunks for word in chunk.text.split()} == {f"w{index}" for index in range(400)}
    assert all((chunk.section_id, chunk.kind, chunk.technique_ids) == ("sec", SourceKind.NIST, ["T1190"]) for chunk in chunks)
    with pytest.raises(ValueError):
        chunk_document(make_document(10), max_tokens=40, overlap_tokens=40)


def test_hash_embedder_is_deterministic_and_normalised() -> None:
    embedder = HashEmbedder()
    first, second, other = embedder.embed(["ARP cache poisoning", "arp CACHE poisoning", "file encryption"])
    assert first == second != other
    assert sum(value * value for value in first) == pytest.approx(1.0)
    assert tokenize("Stops T1557.002, on port-80!") == ["stops", "t1557.002", "on", "port", "80"]


def test_ingest_counts_and_is_idempotent(kb_index: IngestSummary) -> None:
    assert kb_index.documents_by_source == {
        "MITRE ATT&CK": 3, "MITRE D3FEND": 3, "NIST SP 800-53 Rev 5": 3, "Organisation policy": 9,
    }
    assert kb_index.chunks_by_source == kb_index.documents_by_source
    assert (kb_index.total_chunks, kb_index.embedding_model) == (18, "hash-bow-256")
    assert kb_index.skipped_sources == ["CIS Controls: no machine-readable source is configured"]

    store = KnowledgeStore()
    before = sorted(chunk.id for chunk in store.all_chunks())
    again = build_index(raw_dir=KB_FIXTURES)
    assert again.total_chunks == 18
    assert sorted(chunk.id for chunk in store.all_chunks()) == before
    assert len(before) == len(set(before)) == 18

    stored = next(chunk for chunk in store.all_chunks() if chunk.section_id == "D3-NTA")
    assert (stored.technique_ids, stored.kind, stored.control_family) == (["T1557", "T1557.002"], SourceKind.D3FEND, None)


def test_ingest_works_with_whatever_sources_are_present(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "enterprise-attack.json").write_text((KB_FIXTURES / "enterprise-attack.json").read_text())
    (raw / "d3fend.json").write_text("{ not json")
    loaded, skipped = load_documents(raw, tmp_path / "no_policies")
    assert list(loaded) == ["MITRE ATT&CK"]
    assert len(skipped) == 4
    assert any("MITRE D3FEND: could not be parsed" in note for note in skipped)
    assert any("NIST SP 800-53 Rev 5: NIST_SP-800-53_rev5_catalog.json not found" in note for note in skipped)

    summary = build_index(raw_dir=raw, policies_dir=tmp_path / "no_policies")
    assert summary.total_chunks == 3

    empty = build_index(raw_dir=tmp_path / "nothing", policies_dir=tmp_path / "no_policies")
    assert empty.total_chunks == 0
    assert KnowledgeStore().status().ready is False


def test_status_before_and_after_ingest() -> None:
    store = KnowledgeStore()
    assert store.status().model_dump() == {
        "ready": False, "collection": "cyber_kb", "total_chunks": 0, "chunks_by_source": {},
        "chunks_by_kind": {}, "embedding_model": None, "last_ingest_at": None,
    }
    assert store.all_chunks() == [] and store.vector_search([0.0] * 256, 3) == []

    summary = build_index(raw_dir=KB_FIXTURES)
    status = store.status()
    assert (status.ready, status.total_chunks, status.embedding_model) == (True, 18, "hash-bow-256")
    assert status.chunks_by_kind == {"attack": 3, "d3fend": 3, "nist": 3, "policy": 9}
    assert status.chunks_by_source["MITRE ATT&CK"] == 3
    assert status.chunks_by_source["Organisation policy: ACME Network Access Policy"] == 4
    assert status.last_ingest_at == summary.ingested_at


def test_rank_helpers() -> None:
    fused = reciprocal_rank_fusion([["a", "b", "c"], ["b", "a", "d"]])
    assert fused["a"] == pytest.approx(1 / 61 + 1 / 62)
    assert fused["a"] == pytest.approx(fused["b"])
    assert fused["c"] == pytest.approx(1 / 63) and fused["d"] == pytest.approx(1 / 63)
    assert bm25_rank("anything", []) == []


def test_retrieve_returns_arp_and_d3fend_content_for_t1557_002(kb_index: IngestSummary) -> None:
    results = retrieve("ARP cache poisoning on the access switch: detection and mitigation", ["T1557.002"], k=6)

    assert len(results) == 6
    by_section = {result.section_id: result for result in results}
    assert len(by_section) == 6
    arp = by_section["T1557.002"]
    assert (arp.kind, arp.source_name) == (SourceKind.ATTACK, "MITRE ATT&CK")
    assert arp.source_url == "https://attack.mitre.org/techniques/T1557/002"
    assert "Address Resolution Protocol" in arp.text
    defense = by_section["D3-NTA"]
    assert defense.kind == SourceKind.D3FEND and "T1557.002" in defense.technique_ids
    assert "network_access_policy#layer-2-protection-on-access-switches" in by_section

    scores = [result.score for result in results]
    assert scores == sorted(scores, reverse=True) and scores[0] > 0
    assert [r.section_id for r in results[:3]] == [r.section_id for r in retrieve(
        "ARP cache poisoning on the access switch: detection and mitigation", ["T1557.002"], k=3)]
    assert retrieve("ARP cache poisoning", ["T1557.002"], k=6) == retrieve("ARP cache poisoning", ["T1557.002"], k=6)


def test_retrieve_always_includes_the_technique_and_a_defensive_source(kb_index: IngestSummary) -> None:
    for techniques in (["T1557.002"], ["T1110"], ["T1190"]):
        results = retrieve("quarterly restore test of offline backups", techniques, k=2)
        assert len(results) == 2
        assert any(result.section_id == techniques[0] and result.kind == SourceKind.ATTACK for result in results)
        assert any(result.kind in (SourceKind.D3FEND, SourceKind.NIST) for result in results)

    unknown = retrieve("brute force account lockout", ["T9999"], k=3)
    assert len(unknown) == 3
    assert any(result.kind in (SourceKind.D3FEND, SourceKind.NIST) for result in unknown)


def test_retrieve_on_an_empty_index_returns_nothing() -> None:
    assert retrieve("anything", ["T1557.002"]) == []
    build_index(raw_dir=KB_FIXTURES)
    assert retrieve("anything", ["T1557.002"], k=0) == []


def test_store_is_safe_to_open_from_several_threads_at_once(kb_index: IngestSummary) -> None:
    from concurrent.futures import ThreadPoolExecutor

    from app.rag import store as store_module

    store_module._clients.clear()
    store_module._chunk_cache.clear()
    with ThreadPoolExecutor(max_workers=8) as pool:
        statuses = list(pool.map(lambda _: KnowledgeStore().status(), range(16)))
        results = list(pool.map(lambda _: len(retrieve("ARP cache poisoning", ["T1557.002"], 4)), range(16)))
    assert all(status.ready and status.total_chunks == 18 for status in statuses)
    assert results == [4] * 16

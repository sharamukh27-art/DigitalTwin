"""Parsers that turn each knowledge base source into normalised Documents.

Every parser takes already-loaded data (or a path) and never touches the network.
"""

import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from app.models.enums import SourceKind
from app.rag.documents import Document

ATTACK_SOURCE = "MITRE ATT&CK"
D3FEND_SOURCE = "MITRE D3FEND"
NIST_SOURCE = "NIST SP 800-53 Rev 5"
POLICY_SOURCE = "Organisation policy"

ATTACK_URL = "https://attack.mitre.org/techniques/{path}"
D3FEND_URL = "https://d3fend.mitre.org/technique/{name}"
NIST_URL = "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final"
POLICY_URL = "org-policy://{file}#{anchor}"

TECHNIQUE_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_CITATION = re.compile(r"\(Citation:[^)]*\)")
_MARKDOWN_LINK = re.compile(r"\[([^\]]+)\]\([^)]+\)")
_HTML_TAG = re.compile(r"</?[a-zA-Z][^>]*>")
_OSCAL_INSERT = re.compile(r"\{\{\s*insert:\s*param,\s*([^}\s]+)\s*\}\}")
_WHITESPACE = re.compile(r"[ \t]+")


def clean_text(text: str) -> str:
    """Strip citation markers, markdown links and HTML tags, and tidy whitespace."""
    text = _CITATION.sub("", text)
    text = _MARKDOWN_LINK.sub(r"\1", text)
    text = _HTML_TAG.sub("", text)
    text = _WHITESPACE.sub(" ", text)
    return "\n".join(line.strip() for line in text.splitlines()).strip()


def _is_live(obj: dict[str, Any]) -> bool:
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


def _attack_id(obj: dict[str, Any]) -> str | None:
    for reference in obj.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            return reference.get("external_id")
    return None


# --- MITRE ATT&CK -----------------------------------------------------------


def parse_attack(bundle: dict[str, Any]) -> list[Document]:
    """Return one Document per live ATT&CK technique.

    The text holds the technique description, its detection guidance and its
    mitigations. Detection comes from the technique's own `x_mitre_detection` field
    when present, and otherwise from the objects linked by `detects` relationships
    (detection strategies with their analytics, or data components).
    """
    objects = bundle.get("objects", [])
    by_id = {obj["id"]: obj for obj in objects if "id" in obj}
    detections: dict[str, list[str]] = {}
    mitigations: dict[str, list[str]] = {}

    for relation in objects:
        if relation.get("type") != "relationship" or not _is_live(relation):
            continue
        source = by_id.get(relation.get("source_ref", ""))
        target = relation.get("target_ref", "")
        if source is None or not _is_live(source):
            continue
        if relation.get("relationship_type") == "mitigates":
            detail = relation.get("description") or source.get("description", "")
            label = f"{_attack_id(source) or ''} {source.get('name', '')}".strip()
            mitigations.setdefault(target, []).append(f"{label}: {clean_text(detail)}")
        elif relation.get("relationship_type") == "detects":
            parts = [relation.get("description") or source.get("description", "")]
            for analytic_id in source.get("x_mitre_analytic_refs", []):
                analytic = by_id.get(analytic_id)
                if analytic is not None and _is_live(analytic):
                    parts.append(analytic.get("description", ""))
            detail = " ".join(clean_text(part) for part in parts if part)
            detections.setdefault(target, []).append(f"{source.get('name', '')}: {detail}".strip(": "))

    documents: list[Document] = []
    for obj in objects:
        if obj.get("type") != "attack-pattern" or not _is_live(obj):
            continue
        technique_id = _attack_id(obj)
        if technique_id is None:
            continue
        sections = [f"{technique_id} {obj.get('name', '')}", clean_text(obj.get("description", ""))]
        detection = [clean_text(obj["x_mitre_detection"])] if obj.get("x_mitre_detection") else []
        detection.extend(sorted(detections.get(obj["id"], [])))
        if detection:
            sections.append("Detection:\n" + "\n".join(f"- {item}" for item in detection))
        if mitigations.get(obj["id"]):
            sections.append(
                "Mitigations:\n" + "\n".join(f"- {item}" for item in sorted(mitigations[obj["id"]]))
            )
        documents.append(
            Document(
                id=f"attack:{technique_id}",
                text="\n\n".join(section for section in sections if section),
                source_name=ATTACK_SOURCE,
                source_url=ATTACK_URL.format(path=technique_id.replace(".", "/")),
                section_id=technique_id,
                technique_ids=[technique_id],
                kind=SourceKind.ATTACK,
            )
        )
    return sorted(documents, key=lambda document: document.section_id)


# --- MITRE D3FEND -----------------------------------------------------------

_D3FEND_NON_ARTIFACT_KEYS = frozenset(
    {
        "@id", "@type", "rdfs:subClassOf", "rdfs:label", "rdfs:seeAlso", "rdfs:isDefinedBy",
        "rdfs:comment", "skos:altLabel", "d3f:definition", "d3f:attack-id", "d3f:d3fend-id",
        "d3f:kb-article", "d3f:kb-reference", "d3f:synonym", "d3f:created", "d3f:display-order",
        "d3f:todo", "d3f:release-date", "d3f:enables",
    }
)


def _refs(value: Any) -> list[str]:
    """Return the @id values of a JSON-LD property that holds one or more references."""
    values = value if isinstance(value, list) else [value]
    return [item["@id"] for item in values if isinstance(item, dict) and "@id" in item]


class _D3fendGraph:
    """Lookup helpers over the D3FEND JSON-LD graph."""

    def __init__(self, graph: Iterable[dict[str, Any]]) -> None:
        self.nodes = {node["@id"]: node for node in graph if "@id" in node}

    def parents(self, node_id: str) -> list[str]:
        node = self.nodes.get(node_id, {})
        return [ref for ref in _refs(node.get("rdfs:subClassOf", [])) if not ref.startswith("_:")]

    def ancestors(self, node_id: str) -> set[str]:
        seen: set[str] = set()
        stack = self.parents(node_id)
        while stack:
            current = stack.pop()
            if current not in seen:
                seen.add(current)
                stack.extend(self.parents(current))
        return seen

    def artifacts(self, node_id: str) -> set[str]:
        """Return the digital artifacts a technique is related to, by any relation."""
        node = self.nodes.get(node_id, {})
        found: set[str] = set()
        for key, value in node.items():
            if key not in _D3FEND_NON_ARTIFACT_KEYS:
                found.update(ref for ref in _refs(value) if not ref.startswith("_:"))
        for parent in _refs(node.get("rdfs:subClassOf", [])):
            restriction = self.nodes.get(parent, {})
            if parent.startswith("_:") and "owl:someValuesFrom" in restriction:
                found.update(_refs(restriction["owl:someValuesFrom"]))
        return found


def parse_d3fend(ontology: dict[str, Any]) -> list[Document]:
    """Return one Document per D3FEND defensive technique, with the ATT&CK techniques it counters.

    D3FEND links defensive and offensive techniques through shared digital artifacts.
    A defensive technique is mapped to an ATT&CK technique when it acts on an artifact
    that the ATT&CK technique (or one of its parent techniques) touches, or on a more
    general class of that artifact. When several nodes share a D3FEND id, the first
    by node id is kept.
    """
    graph = _D3fendGraph(ontology.get("@graph", []))

    offensive: dict[str, set[str]] = {}
    for node_id, node in graph.nodes.items():
        attack_id = node.get("d3f:attack-id")
        if not isinstance(attack_id, str):
            continue
        chain = [node_id, *[a for a in graph.ancestors(node_id) if "d3f:attack-id" in graph.nodes.get(a, {})]]
        artifacts: set[str] = set()
        for member in chain:
            artifacts |= graph.artifacts(member)
        widened = set(artifacts)
        for artifact in artifacts:
            widened |= graph.ancestors(artifact)
        if widened:
            offensive[attack_id] = widened

    documents: list[Document] = []
    seen: set[str] = set()
    for node_id in sorted(graph.nodes):
        node = graph.nodes[node_id]
        d3fend_id = node.get("d3f:d3fend-id")
        label = node.get("rdfs:label")
        if not isinstance(d3fend_id, str) or not isinstance(label, str) or d3fend_id in seen:
            continue
        seen.add(d3fend_id)
        acts_on = graph.artifacts(node_id)
        countered = sorted(attack_id for attack_id, touched in offensive.items() if acts_on & touched)
        sections = [f"{d3fend_id} {label}", clean_text(str(node.get("d3f:definition", "")))]
        article = node.get("d3f:kb-article")
        if isinstance(article, str) and article.strip():
            sections.append(clean_text(article.replace("#", "")))
        if acts_on:
            names = sorted(artifact.split(":")[-1] for artifact in acts_on)
            sections.append("Acts on: " + ", ".join(names))
        documents.append(
            Document(
                id=f"d3fend:{d3fend_id}",
                text="\n\n".join(section for section in sections if section),
                source_name=D3FEND_SOURCE,
                source_url=D3FEND_URL.format(name=node_id),
                section_id=d3fend_id,
                technique_ids=countered,
                kind=SourceKind.D3FEND,
            )
        )
    return sorted(documents, key=lambda document: document.section_id)


# --- NIST SP 800-53 ---------------------------------------------------------


def _oscal_label(control: dict[str, Any]) -> str:
    """Return the human label of a control, for example AC-2 or AC-2(1)."""
    for prop in control.get("props", []):
        if prop.get("name") == "label" and "class" not in prop:
            return str(prop["value"])
    return str(control.get("id", "")).upper()


def _oscal_prose(part: dict[str, Any], params: dict[str, str]) -> list[str]:
    """Flatten a statement part and its nested items into lines of prose."""
    lines: list[str] = []
    label = next((p["value"] for p in part.get("props", []) if p.get("name") == "label"), "")
    prose = part.get("prose", "")
    if prose:
        filled = _OSCAL_INSERT.sub(lambda match: f"[{params.get(match.group(1), 'organization-defined')}]", prose)
        lines.append(f"{label} {filled}".strip())
    for child in part.get("parts", []):
        lines.extend(_oscal_prose(child, params))
    return lines


def _oscal_controls(
    controls: Iterable[dict[str, Any]], family: str, params: dict[str, str]
) -> Iterable[Document]:
    for control in controls:
        local = dict(params)
        for param in control.get("params", []):
            local[param["id"]] = param.get("label") or "organization-defined"
        status = next((p.get("value") for p in control.get("props", []) if p.get("name") == "status"), None)
        statement = next((p for p in control.get("parts", []) if p.get("name") == "statement"), None)
        if status != "withdrawn" and statement is not None:
            label = _oscal_label(control)
            lines = _oscal_prose(statement, local)
            yield Document(
                id=f"nist:{label}",
                text=f"{label} {control.get('title', '')}\n\n" + "\n".join(lines),
                source_name=NIST_SOURCE,
                source_url=NIST_URL,
                section_id=label,
                control_family=family,
                kind=SourceKind.NIST,
            )
        yield from _oscal_controls(control.get("controls", []), family, local)


def parse_nist(catalog: dict[str, Any]) -> list[Document]:
    """Return one Document per NIST SP 800-53 control and enhancement that has a statement."""
    documents: list[Document] = []
    for group in catalog.get("catalog", {}).get("groups", []):
        documents.extend(_oscal_controls(group.get("controls", []), group.get("title", ""), {}))
    return documents


# --- organisation policies --------------------------------------------------


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "section"


def parse_policy(path: Path) -> list[Document]:
    """Return one Document per `##` section of a policy markdown file.

    Technique ids mentioned in a section (for example T1557.002) become its technique_ids.
    """
    text = path.read_text(encoding="utf-8")
    title_match = re.search(r"^#\s+(.+)$", text, flags=re.MULTILINE)
    title = title_match.group(1).strip() if title_match else path.stem
    sections = re.split(r"^##\s+", text, flags=re.MULTILINE)[1:]
    documents: list[Document] = []
    for section in sections:
        heading, _, body = section.partition("\n")
        heading = heading.strip()
        if not body.strip():
            continue
        anchor = _slug(heading)
        documents.append(
            Document(
                id=f"policy:{path.stem}#{anchor}",
                text=f"{title}: {heading}\n\n{clean_text(body)}",
                source_name=f"{POLICY_SOURCE}: {title}",
                source_url=POLICY_URL.format(file=path.name, anchor=anchor),
                section_id=f"{path.stem}#{anchor}",
                technique_ids=sorted(set(TECHNIQUE_PATTERN.findall(body))),
                kind=SourceKind.POLICY,
            )
        )
    return documents

"""Core domain data contracts for cmd-unmask."""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Deterministic triage severity classification."""

    BENIGN = "BENIGN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        order = {
            Severity.BENIGN: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return order[self]


@dataclass(frozen=True)
class TriageConfig:
    """Configuration parameters governing unpacking and triage bounds."""

    max_depth: int = 10
    max_nodes: int = 64
    max_stream_bytes: int = 262_144
    timeout_seconds: float = 3.0
    defang_iocs: bool = True
    custom_field: str | None = None


@dataclass
class IngestionRecord:
    """A single command artifact produced by the Ingestion Pipeline."""

    source_id: str
    raw_input: str
    command_text: str
    warnings: list[str] = field(default_factory=list)


def compute_printable_ratio(text: str) -> float:
    """Calculate the ratio of printable characters (including common whitespace) in text."""
    if not text:
        return 0.0
    printable_count = sum(
        1 for ch in text if ch.isprintable() or ch in ("\n", "\r", "\t")
    )
    return round(printable_count / len(text), 4)


def compute_shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy in bits per byte over UTF-8 encoded text."""
    data = text.encode("utf-8", errors="replace")
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 4)


@dataclass
class PayloadNode:
    """A distinct command or decoded artifact state within the Unpacking DAG."""

    node_id: str
    text: str
    depth: int
    parent_id: str | None = None
    technique: str = "root"
    parameters: dict[str, Any] = field(default_factory=dict)
    is_reconstructed_command: bool = False
    sha256: str = ""
    printable_ratio: float = 0.0
    shannon_entropy: float = 0.0

    def __post_init__(self) -> None:
        if not self.sha256:
            self.sha256 = hashlib.sha256(self.text.encode("utf-8", errors="replace")).hexdigest()
        if self.printable_ratio == 0.0 and self.text:
            self.printable_ratio = compute_printable_ratio(self.text)
        if self.shannon_entropy == 0.0 and self.text:
            self.shannon_entropy = compute_shannon_entropy(self.text)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "sha256": self.sha256,
            "text": self.text,
            "depth": self.depth,
            "parent_id": self.parent_id,
            "technique": self.technique,
            "parameters": dict(self.parameters),
            "is_reconstructed_command": self.is_reconstructed_command,
            "printable_ratio": self.printable_ratio,
            "shannon_entropy": self.shannon_entropy,
        }


@dataclass
class ProvenanceStep:
    """A single parent-to-child transformation link in the Provenance Chain."""

    parent_id: str
    child_id: str
    technique: str
    parameters: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "parent_id": self.parent_id,
            "child_id": self.child_id,
            "technique": self.technique,
            "parameters": dict(self.parameters),
        }


@dataclass
class UnpackingDAG:
    """Bounded directed acyclic graph of decoded payload states explored from a root command."""

    root_id: str
    nodes: dict[str, PayloadNode] = field(default_factory=dict)
    edges: list[ProvenanceStep] = field(default_factory=list)
    primary_leaf_id: str = ""
    truncated: bool = False
    warnings: list[str] = field(default_factory=list)

    def get_provenance_chain(self, target_node_id: str | None = None) -> list[ProvenanceStep]:
        """Return ordered ProvenanceStep chain from root to target_node_id (defaults to primary_leaf_id)."""
        node_id = target_node_id or self.primary_leaf_id or self.root_id
        edge_by_child = {edge.child_id: edge for edge in self.edges}
        chain: list[ProvenanceStep] = []
        curr = node_id
        visited: set[str] = set()
        while curr in edge_by_child and curr not in visited:
            visited.add(curr)
            edge = edge_by_child[curr]
            chain.append(edge)
            curr = edge.parent_id
        chain.reverse()
        return chain

    def get_leaf_nodes(self) -> list[PayloadNode]:
        """Return all terminal leaf PayloadNodes in the DAG."""
        parent_ids = {edge.parent_id for edge in self.edges}
        leaves = [node for nid, node in self.nodes.items() if nid not in parent_ids]
        return leaves or ([self.nodes[self.root_id]] if self.root_id in self.nodes else [])


@dataclass
class ExtractedIOC:
    """An Indicator of Compromise harvested from a Payload Node."""

    ioc_type: str
    raw_value: str
    defanged_value: str
    source_node_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "ioc_type": self.ioc_type,
            "raw_value": self.raw_value,
            "defanged_value": self.defanged_value,
            "source_node_id": self.source_node_id,
        }


@dataclass
class BehavioralMatch:
    """A behavioral or LOLBin rule hit mapped to MITRE ATT&CK."""

    rule_id: str
    name: str
    mitre_id: str
    tactic: str
    weight: int
    evidence: str
    source_node_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "mitre_id": self.mitre_id,
            "tactic": self.tactic,
            "weight": self.weight,
            "evidence": self.evidence,
            "source_node_id": self.source_node_id,
        }


@dataclass
class TriageVerdict:
    """Final structured assessment produced by cmd-unmask for SOC ticketing."""

    source_id: str
    original_command: str
    primary_unmasked_payload: str
    dag: UnpackingDAG
    provenance_chain: list[ProvenanceStep] = field(default_factory=list)
    leaf_payloads: list[str] = field(default_factory=list)
    iocs: list[ExtractedIOC] = field(default_factory=list)
    behavioral_matches: list[BehavioralMatch] = field(default_factory=list)
    risk_score: int = 0
    severity: Severity = Severity.BENIGN
    warnings: list[str] = field(default_factory=list)

    def to_dict(self, defang: bool = True) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "original_command": self.original_command,
            "primary_unmasked_payload": self.primary_unmasked_payload,
            "severity": self.severity.value,
            "risk_score": self.risk_score,
            "provenance_chain": [step.to_dict() for step in self.provenance_chain],
            "leaf_payloads": list(self.leaf_payloads),
            "iocs": [
                {
                    **ioc.to_dict(),
                    "value": ioc.defanged_value if defang else ioc.raw_value,
                }
                for ioc in self.iocs
            ],
            "behavioral_matches": [m.to_dict() for m in self.behavioral_matches],
            "dag": {
                "root_id": self.dag.root_id,
                "primary_leaf_id": self.dag.primary_leaf_id,
                "truncated": self.dag.truncated,
                "nodes": {nid: node.to_dict() for nid, node in self.dag.nodes.items()},
                "edges": [edge.to_dict() for edge in self.dag.edges],
            },
            "warnings": list(self.warnings),
        }

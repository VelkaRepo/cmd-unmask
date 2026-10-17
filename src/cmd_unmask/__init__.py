"""cmd-unmask: Static command-line de-obfuscation and behavioral triage Tracer Script."""

from cmd_unmask.models import (
    BehavioralMatch,
    ExtractedIOC,
    IngestionRecord,
    PayloadNode,
    ProvenanceStep,
    Severity,
    TriageConfig,
    TriageVerdict,
    UnpackingDAG,
)
from cmd_unmask.unpacker import unmask_command, unpack_dag

__all__ = [
    "BehavioralMatch",
    "ExtractedIOC",
    "IngestionRecord",
    "PayloadNode",
    "ProvenanceStep",
    "Severity",
    "TriageConfig",
    "TriageVerdict",
    "UnpackingDAG",
    "unmask_command",
    "unpack_dag",
]

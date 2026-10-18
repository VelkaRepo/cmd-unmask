"""cmd-unmask: Static command-line de-obfuscation and behavioral triage Tracer Script."""

from cmd_unmask.ingestion import ingest_single_command, ingest_source, unescape_siem_wrapper
from cmd_unmask.ioc import defang_ioc, extract_iocs, extract_iocs_from_text
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
from cmd_unmask.normalizer import NormalizationResult, normalize, normalize_shell
from cmd_unmask.resolver import ExpressionResolutionResult, resolve_expression_node, resolve_expressions
from cmd_unmask.unpacker import unmask_command, unpack_dag

__all__ = [
    "BehavioralMatch",
    "ExtractedIOC",
    "IngestionRecord",
    "NormalizationResult",
    "PayloadNode",
    "ProvenanceStep",
    "Severity",
    "TriageConfig",
    "TriageVerdict",
    "UnpackingDAG",
    "ingest_single_command",
    "ingest_source",
    "ExpressionResolutionResult",
    "normalize",
    "normalize_shell",
    "resolve_expression_node",
    "resolve_expressions",
    "unescape_siem_wrapper",
    "unmask_command",
    "unpack_dag",
]

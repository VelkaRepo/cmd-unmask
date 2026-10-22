"""cmd-unmask: Static command-line de-obfuscation and behavioral triage Tracer Script."""

from cmd_unmask.classifier import classify_dag, classify_node_text, score_verdict
from cmd_unmask.ingestion import ingest_single_command, ingest_source, unescape_siem_wrapper
from cmd_unmask.ioc import (
    CLOUD_METADATA_ENDPOINTS,
    CLOUD_METADATA_IPS,
    defang_ioc,
    extract_iocs,
    extract_iocs_from_text,
)
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
from cmd_unmask.renderer import (
    build_soc_ticket_note,
    build_unmasking_timeline,
    render_json,
    render_jsonl,
    render_markdown,
    render_pretty,
)
from cmd_unmask.resolver import ExpressionResolutionResult, resolve_expression_node, resolve_expressions
from cmd_unmask.unpacker import unmask_command, unpack_dag

__all__ = [
    "BehavioralMatch",
    "CLOUD_METADATA_ENDPOINTS",
    "CLOUD_METADATA_IPS",
    "ExtractedIOC",
    "IngestionRecord",
    "NormalizationResult",
    "PayloadNode",
    "ProvenanceStep",
    "Severity",
    "TriageConfig",
    "TriageVerdict",
    "UnpackingDAG",
    "build_soc_ticket_note",
    "build_unmasking_timeline",
    "classify_dag",
    "classify_node_text",
    "defang_ioc",
    "extract_iocs",
    "extract_iocs_from_text",
    "ingest_single_command",
    "ingest_source",
    "ExpressionResolutionResult",
    "normalize",
    "normalize_shell",
    "render_json",
    "render_jsonl",
    "render_markdown",
    "render_pretty",
    "resolve_expression_node",
    "resolve_expressions",
    "score_verdict",
    "unescape_siem_wrapper",
    "unmask_command",
    "unpack_dag",
]

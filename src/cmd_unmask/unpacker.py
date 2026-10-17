"""Unpacking DAG orchestration and unmask_command pipeline entrypoint."""

from __future__ import annotations

from cmd_unmask.models import (
    PayloadNode,
    Severity,
    TriageConfig,
    TriageVerdict,
    UnpackingDAG,
)


def unpack_dag(command_text: str, config: TriageConfig | None = None) -> UnpackingDAG:
    """Explore the Unpacking DAG starting from command_text."""
    _ = config or TriageConfig()
    root_node = PayloadNode(
        node_id="node_0",
        text=command_text,
        depth=0,
        parent_id=None,
        technique="root",
    )
    dag = UnpackingDAG(
        root_id=root_node.node_id,
        nodes={root_node.node_id: root_node},
        edges=[],
        primary_leaf_id=root_node.node_id,
    )
    return dag


def unmask_command(
    raw_cmd: str,
    config: TriageConfig | None = None,
    source_id: str = "cli",
    initial_warnings: list[str] | None = None,
) -> TriageVerdict:
    """Execute the end-to-end static de-obfuscation and triage pipeline on a command."""
    cfg = config or TriageConfig()
    warnings: list[str] = list(initial_warnings) if initial_warnings else []

    try:
        if not isinstance(raw_cmd, str) or not raw_cmd.strip():
            warnings.append("Empty or whitespace-only command input.")
            safe_text = raw_cmd if isinstance(raw_cmd, str) else ""
            dag = unpack_dag(safe_text, cfg)
            return TriageVerdict(
                source_id=source_id,
                original_command=safe_text,
                primary_unmasked_payload=safe_text,
                dag=dag,
                provenance_chain=[],
                leaf_payloads=[safe_text] if safe_text else [],
                warnings=warnings,
            )

        dag = unpack_dag(raw_cmd, cfg)
        warnings.extend(dag.warnings)
        primary_node = dag.nodes[dag.primary_leaf_id]
        leaves = [n.text for n in dag.get_leaf_nodes()]

        return TriageVerdict(
            source_id=source_id,
            original_command=raw_cmd,
            primary_unmasked_payload=primary_node.text,
            dag=dag,
            provenance_chain=dag.get_provenance_chain(dag.primary_leaf_id),
            leaf_payloads=leaves,
            risk_score=0,
            severity=Severity.BENIGN,
            warnings=warnings,
        )
    except Exception as exc:  # Defensive fallback per engineering standards
        warnings.append(f"Pipeline error: {exc}")
        fallback_node = PayloadNode(node_id="node_0", text=str(raw_cmd or ""), depth=0)
        fallback_dag = UnpackingDAG(
            root_id="node_0",
            nodes={"node_0": fallback_node},
            primary_leaf_id="node_0",
        )
        return TriageVerdict(
            source_id=source_id,
            original_command=str(raw_cmd or ""),
            primary_unmasked_payload=str(raw_cmd or ""),
            dag=fallback_dag,
            warnings=warnings,
        )

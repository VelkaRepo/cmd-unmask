"""Unpacking DAG orchestration and unmask_command pipeline entrypoint."""

from __future__ import annotations

from cmd_unmask.models import (
    PayloadNode,
    ProvenanceStep,
    Severity,
    TriageConfig,
    TriageVerdict,
    UnpackingDAG,
)
from cmd_unmask.normalizer import normalize_shell
from cmd_unmask.resolver import resolve_expression_node


def unpack_dag(command_text: str, config: TriageConfig | None = None) -> UnpackingDAG:
    """Explore the Unpacking DAG starting from command_text."""
    cfg = config or TriageConfig()
    root_node = PayloadNode(
        node_id="node_0",
        text=command_text,
        depth=0,
        parent_id=None,
        technique="root",
    )
    nodes: dict[str, PayloadNode] = {root_node.node_id: root_node}
    edges: list[ProvenanceStep] = []
    seen_hashes: dict[str, str] = {root_node.sha256: root_node.node_id}
    primary_leaf_id = root_node.node_id

    # Step A: Shell Normalizer pass
    if root_node.depth < cfg.max_depth and len(nodes) < cfg.max_nodes:
        norm_res = normalize_shell(root_node.text)
        if norm_res.modified:
            child_node = PayloadNode(
                node_id=f"node_{len(nodes)}",
                text=norm_res.normalized_text,
                depth=root_node.depth + 1,
                parent_id=root_node.node_id,
                technique="shell_normalizer",
                parameters={
                    "passes": norm_res.applied_passes,
                    "resolved_env_vars": norm_res.resolved_env_vars,
                },
                is_reconstructed_command=True,
            )
            if child_node.sha256 not in seen_hashes:
                seen_hashes[child_node.sha256] = child_node.node_id
                nodes[child_node.node_id] = child_node
                edges.append(
                    ProvenanceStep(
                        parent_id=root_node.node_id,
                        child_id=child_node.node_id,
                        technique="shell_normalizer",
                        parameters=dict(child_node.parameters),
                    )
                )
                primary_leaf_id = child_node.node_id

    # Step B: Static Expression Resolver pass
    current_node = nodes[primary_leaf_id]
    if current_node.depth < cfg.max_depth and len(nodes) < cfg.max_nodes:
        expr_res = resolve_expression_node(current_node.text)
        if expr_res.modified:
            expr_child = PayloadNode(
                node_id=f"node_{len(nodes)}",
                text=expr_res.resolved_text,
                depth=current_node.depth + 1,
                parent_id=current_node.node_id,
                technique="expression_resolver",
                parameters={
                    "passes_run": expr_res.passes_run,
                    "reducers": expr_res.applied_reducers,
                },
                is_reconstructed_command=True,
            )
            if expr_child.sha256 not in seen_hashes:
                seen_hashes[expr_child.sha256] = expr_child.node_id
                nodes[expr_child.node_id] = expr_child
                edges.append(
                    ProvenanceStep(
                        parent_id=current_node.node_id,
                        child_id=expr_child.node_id,
                        technique="expression_resolver",
                        parameters=dict(expr_child.parameters),
                    )
                )
                primary_leaf_id = expr_child.node_id

    dag = UnpackingDAG(
        root_id=root_node.node_id,
        nodes=nodes,
        edges=edges,
        primary_leaf_id=primary_leaf_id,
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

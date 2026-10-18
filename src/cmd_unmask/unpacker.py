"""Unpacking DAG orchestration and unmask_command pipeline entrypoint."""

from __future__ import annotations

import base64
import re
import time
import urllib.parse
import zlib
from collections import deque
from typing import Any

from cmd_unmask.ioc import extract_iocs, extract_iocs_from_text
from cmd_unmask.models import (
    PayloadNode,
    ProvenanceStep,
    Severity,
    TriageConfig,
    TriageVerdict,
    UnpackingDAG,
    compute_printable_ratio,
    compute_shannon_entropy,
)
from cmd_unmask.normalizer import normalize_shell
from cmd_unmask.resolver import resolve_expression_node

MIN_PRINTABLE_RATIO: float = 0.85
MAX_SHANNON_ENTROPY: float = 6.2
XOR_BRUTEFORCE_MIN_PRINTABLE: float = 0.92

_B64_SPAN_RE = re.compile(
    r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{16,}={0,2})(?![A-Za-z0-9+/=_-])"
)
_HEX_SPAN_RE = re.compile(r"(?<![0-9A-Za-z_])(?:0x)?([0-9a-fA-F]{24,})(?![0-9A-Za-z_])")
_URL_ENCODED_RE = re.compile(r"(?:%[0-9a-fA-F]{2}){2,}")
_CHARCODE_SEQ_RE = re.compile(
    r"(?:fromCharCode\s*\(\s*)?((?:0x[0-9a-fA-F]+|\d{2,3})(?:\s*,\s*(?:0x[0-9a-fA-F]+|\d{2,3})){5,})\s*\)?",
    re.IGNORECASE,
)
_EXPLICIT_XOR_KEY_RE = re.compile(
    r"(?:-bxor|\bxor\b)\s*(0x[0-9a-fA-F]+|\d+)",
    re.IGNORECASE,
)

_XOR_ANCHOR_RE = re.compile(
    r"(?:https?://|powershell|cmd\.exe|\biex\b|invoke-|downloadstring|webclient|mshta|rundll32|regsvr32|certutil|/bin/(?:ba)?sh|\bcurl\b|\bwget\b)",
    re.IGNORECASE,
)


def _passes_rigidity_gate(text: str, min_printable: float = MIN_PRINTABLE_RATIO) -> bool:
    """Check whether decoded candidate text satisfies Detection Rigidity thresholds."""
    stripped = text.strip()
    if len(stripped) < 4:
        return False
    if any(ord(ch) < 32 and ord(ch) not in (9, 10, 13) for ch in stripped):
        return False
    if "\ufffd" in stripped and stripped.count("\ufffd") / len(stripped) > 0.05:
        return False
    pr = compute_printable_ratio(stripped)
    ent = compute_shannon_entropy(stripped)
    return pr >= min_printable and ent <= MAX_SHANNON_ENTROPY


def _decode_bytes_to_text(raw_bytes: bytes) -> tuple[str, str] | None:
    """Attempt UTF-16LE or UTF-8 decoding on raw bytes if it passes Detection Rigidity."""
    if not raw_bytes:
        return None

    if len(raw_bytes) >= 4 and len(raw_bytes) % 2 == 0:
        odd_nulls = sum(1 for idx in range(1, len(raw_bytes), 2) if raw_bytes[idx] == 0)
        half_len = len(raw_bytes) // 2
        if odd_nulls / half_len >= 0.35:
            try:
                text16 = raw_bytes.decode("utf-16le")
                if _passes_rigidity_gate(text16):
                    return text16, "utf-16le"
            except Exception:
                pass

    try:
        text8 = raw_bytes.decode("utf-8")
        if _passes_rigidity_gate(text8):
            return text8, "utf-8"
    except Exception:
        pass

    return None


def _chunked_decompress(
    data: bytes,
    wbits: int,
    max_bytes: int,
) -> tuple[bytes | None, str | None]:
    """Safely decompress Gzip/Deflate stream in chunks while enforcing max_bytes ceiling."""
    try:
        decompressor = zlib.decompressobj(wbits)
        chunks: list[bytes] = []
        total = 0
        mv = memoryview(data)
        step = 4096
        for offset in range(0, len(mv), step):
            remaining = max_bytes - total + 1
            piece = decompressor.decompress(mv[offset : offset + step], remaining)
            total += len(piece)
            if total > max_bytes:
                return None, f"Decompressed stream exceeded max_stream_bytes limit ({max_bytes} bytes)."
            chunks.append(piece)
            if decompressor.unconsumed_tail:
                while decompressor.unconsumed_tail:
                    rem = max_bytes - total + 1
                    extra = decompressor.decompress(decompressor.unconsumed_tail, rem)
                    total += len(extra)
                    if total > max_bytes:
                        return (
                            None,
                            f"Decompressed stream exceeded max_stream_bytes limit ({max_bytes} bytes).",
                        )
                    chunks.append(extra)
        tail = decompressor.flush()
        total += len(tail)
        if total > max_bytes:
            return None, f"Decompressed stream exceeded max_stream_bytes limit ({max_bytes} bytes)."
        chunks.append(tail)
        return b"".join(chunks), None
    except Exception:
        return None, None


def _try_decode_base64_span(token: str) -> bytes | None:
    """Decode standard or URL-safe Base64 token with automatic '=' padding repair."""
    cleaned = token.strip()
    if re.fullmatch(r"[0-9a-fA-F]+", cleaned) and len(cleaned) % 2 == 0 and len(cleaned) >= 24:
        return None
    if cleaned.isalpha() and (cleaned.islower() or cleaned.isupper()) and len(cleaned) < 28:
        return None
    normalized = cleaned.replace("-", "+").replace("_", "/")
    pad_mod = len(normalized.rstrip("=")) % 4
    if pad_mod == 1:
        return None
    raw_unpadded = normalized.rstrip("=")
    if pad_mod in (2, 3):
        raw_unpadded += "=" * (4 - pad_mod)
    try:
        return base64.b64decode(raw_unpadded, validate=True)
    except Exception:
        return None


def _splice_reconstructed(parent_text: str, span_start: int, span_end: int, decoded: str) -> str:
    """Splice a decoded span back into its surrounding parent command syntax."""
    prefix = parent_text[:span_start]
    suffix = parent_text[span_end:]

    enc_flag_re = re.compile(
        r"(-(?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+)['\"]?$",
        re.IGNORECASE,
    )
    if enc_flag_re.search(prefix):
        prefix_clean = enc_flag_re.sub("-c ", prefix)
        suffix_clean = suffix[1:] if suffix and suffix[0] in ("'", '"') else suffix
        return f"{prefix_clean}{decoded}{suffix_clean}".strip()

    return f"{prefix}{decoded}{suffix}".strip()


def _extract_explicit_xor_keys(text: str) -> list[int]:
    """Extract explicit XOR byte keys from -bxor or xor syntax in the command."""
    keys: list[int] = []
    for m in _EXPLICIT_XOR_KEY_RE.finditer(text):
        raw_k = m.group(1)
        try:
            val = int(raw_k, 16) if raw_k.lower().startswith("0x") else int(raw_k, 10)
            if 1 <= val <= 0xFF and val not in keys:
                keys.append(val)
        except ValueError:
            pass
    return keys


def _try_fallback_xor_bruteforce(raw_bytes: bytes) -> tuple[str, int] | None:
    """Attempt 1-byte XOR brute-force (0x01..0xFF) with strict >=0.92 printable + anchor gate."""
    if len(raw_bytes) < 16:
        return None
    for key in range(1, 256):
        xored = bytes(b ^ key for b in raw_bytes)
        try:
            candidate = xored.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if compute_printable_ratio(candidate) >= XOR_BRUTEFORCE_MIN_PRINTABLE:
            if _XOR_ANCHOR_RE.search(candidate):
                return candidate, key
    return None


def _rank_leaf_node(node: PayloadNode) -> tuple[int, int, int, float]:
    """Compute deterministic ranking tuple for selecting the Primary Unmasked Payload."""
    anchor_hits = len(_XOR_ANCHOR_RE.findall(node.text))
    ioc_hits = len(extract_iocs_from_text(node.text, source_node_id=node.node_id))
    return (
        1 if node.is_reconstructed_command else 0,
        node.depth,
        anchor_hits + ioc_hits,
        node.printable_ratio,
    )


def unpack_dag(command_text: str, config: TriageConfig | None = None) -> UnpackingDAG:
    """Explore the bounded Unpacking DAG starting from command_text."""
    cfg = config or TriageConfig()
    start_time = time.monotonic()

    root_node = PayloadNode(
        node_id="node_0",
        text=command_text,
        depth=0,
        parent_id=None,
        technique="root",
        is_reconstructed_command=True,
    )
    nodes: dict[str, PayloadNode] = {root_node.node_id: root_node}
    edges: list[ProvenanceStep] = []
    seen_hashes: dict[str, str] = {root_node.sha256: root_node.node_id}
    warnings: list[str] = []
    truncated = False

    queue: deque[PayloadNode] = deque([root_node])
    unresolved_binary_blobs: list[tuple[PayloadNode, int, int, bytes]] = []

    def _add_child(
        parent: PayloadNode,
        child_text: str,
        technique: str,
        parameters: dict[str, Any],
        is_reconstructed: bool,
    ) -> PayloadNode | None:
        nonlocal truncated
        if len(nodes) >= cfg.max_nodes:
            truncated = True
            if "Maximum Unpacking DAG node limit reached." not in warnings:
                warnings.append("Maximum Unpacking DAG node limit reached.")
            return None
        if parent.depth >= cfg.max_depth:
            truncated = True
            if "Maximum Unpacking DAG depth limit reached." not in warnings:
                warnings.append("Maximum Unpacking DAG depth limit reached.")
            return None

        candidate = PayloadNode(
            node_id=f"node_{len(nodes)}",
            text=child_text,
            depth=parent.depth + 1,
            parent_id=parent.node_id,
            technique=technique,
            parameters=parameters,
            is_reconstructed_command=is_reconstructed,
        )
        if candidate.sha256 in seen_hashes:
            return None
        seen_hashes[candidate.sha256] = candidate.node_id
        nodes[candidate.node_id] = candidate
        edges.append(
            ProvenanceStep(
                parent_id=parent.node_id,
                child_id=candidate.node_id,
                technique=technique,
                parameters=dict(parameters),
            )
        )
        queue.append(candidate)
        return candidate

    while queue:
        if (time.monotonic() - start_time) > cfg.timeout_seconds:
            truncated = True
            warnings.append(f"Unpacking timeout ({cfg.timeout_seconds}s) exceeded.")
            break

        curr_node = queue.popleft()
        if curr_node.depth >= cfg.max_depth or len(nodes) >= cfg.max_nodes:
            continue

        # Step A: Shell Normalizer pass
        norm_res = normalize_shell(curr_node.text)
        if norm_res.modified:
            _add_child(
                parent=curr_node,
                child_text=norm_res.normalized_text,
                technique="shell_normalizer",
                parameters={
                    "passes": norm_res.applied_passes,
                    "resolved_env_vars": norm_res.resolved_env_vars,
                },
                is_reconstructed=curr_node.is_reconstructed_command,
            )
            continue

        # Step B: Static Expression Resolver pass
        expr_res = resolve_expression_node(curr_node.text)
        if expr_res.modified:
            _add_child(
                parent=curr_node,
                child_text=expr_res.resolved_text,
                technique="expression_resolver",
                parameters={
                    "passes_run": expr_res.passes_run,
                    "reducers": expr_res.applied_reducers,
                },
                is_reconstructed=curr_node.is_reconstructed_command,
            )
            continue

        # Step C: Span Carving & Candidate Decoders
        text = curr_node.text
        explicit_xor_keys = _extract_explicit_xor_keys(text)

        # C1. URL percent-encoding (%XX)
        if _URL_ENCODED_RE.search(text):
            unquoted_url = urllib.parse.unquote(text)
            if unquoted_url != text and _passes_rigidity_gate(unquoted_url):
                _add_child(
                    parent=curr_node,
                    child_text=unquoted_url,
                    technique="url_decode",
                    parameters={},
                    is_reconstructed=True,
                )

        # C2. CharCode sequences
        for m_cc in _CHARCODE_SEQ_RE.finditer(text):
            raw_nums = [t.strip() for t in m_cc.group(1).split(",") if t.strip()]
            chars: list[str] = []
            valid_cc = True
            for tok in raw_nums:
                try:
                    val = int(tok, 16) if tok.lower().startswith("0x") else int(tok, 10)
                    if 9 <= val <= 126:
                        chars.append(chr(val))
                    else:
                        valid_cc = False
                        break
                except ValueError:
                    valid_cc = False
                    break
            if valid_cc and len(chars) >= 6:
                decoded_cc = "".join(chars)
                if _passes_rigidity_gate(decoded_cc):
                    _add_child(
                        parent=curr_node,
                        child_text=decoded_cc,
                        technique="charcode_decode",
                        parameters={"count": len(chars)},
                        is_reconstructed=False,
                    )
                    if m_cc.group(0).strip() != text.strip():
                        spliced = _splice_reconstructed(
                            text, m_cc.start(), m_cc.end(), decoded_cc
                        )
                        _add_child(
                            parent=curr_node,
                            child_text=spliced,
                            technique="charcode_decode",
                            parameters={"count": len(chars), "reconstructed": True},
                            is_reconstructed=True,
                        )

        # C3. Hex spans
        for m_hex in _HEX_SPAN_RE.finditer(text):
            hex_str = m_hex.group(1)
            if len(hex_str) % 2 != 0:
                continue
            try:
                raw_hex_bytes = bytes.fromhex(hex_str)
            except ValueError:
                continue
            decoded_pair = _decode_bytes_to_text(raw_hex_bytes)
            if decoded_pair is not None:
                decoded_hex, enc_used = decoded_pair
                _add_child(
                    parent=curr_node,
                    child_text=decoded_hex,
                    technique="hex_decode",
                    parameters={"encoding": enc_used},
                    is_reconstructed=False,
                )
                if m_hex.group(0).strip() != text.strip():
                    spliced = _splice_reconstructed(
                        text, m_hex.start(), m_hex.end(), decoded_hex
                    )
                    _add_child(
                        parent=curr_node,
                        child_text=spliced,
                        technique="hex_decode",
                        parameters={"encoding": enc_used, "reconstructed": True},
                        is_reconstructed=True,
                    )

        # C4. Base64 spans (standard + URL-safe, unpadded, UTF-16LE/UTF-8, Gzip/Deflate, XOR)
        for m_b64 in _B64_SPAN_RE.finditer(text):
            span_str = m_b64.group(1)
            raw_b64 = _try_decode_base64_span(span_str)
            if raw_b64 is None:
                continue

            if raw_b64.startswith(b"\x1f\x8b"):
                decomp, err = _chunked_decompress(
                    raw_b64, 16 + zlib.MAX_WBITS, cfg.max_stream_bytes
                )
                if err:
                    warnings.append(err)
                    truncated = True
                    continue
                if decomp is not None:
                    dec_pair = _decode_bytes_to_text(decomp)
                    if dec_pair is not None:
                        dec_text, enc_used = dec_pair
                        _add_child(
                            parent=curr_node,
                            child_text=dec_text,
                            technique="base64_gzip_decode",
                            parameters={"encoding": enc_used},
                            is_reconstructed=False,
                        )
                        if span_str != text.strip():
                            spliced = _splice_reconstructed(
                                text, m_b64.start(), m_b64.end(), dec_text
                            )
                            _add_child(
                                parent=curr_node,
                                child_text=spliced,
                                technique="base64_gzip_decode",
                                parameters={"encoding": enc_used, "reconstructed": True},
                                is_reconstructed=True,
                            )
                        continue

            if "deflatestream" in text.lower() or "io.compression" in text.lower():
                for wbits in (-zlib.MAX_WBITS, zlib.MAX_WBITS):
                    decomp, err = _chunked_decompress(raw_b64, wbits, cfg.max_stream_bytes)
                    if err:
                        warnings.append(err)
                        truncated = True
                        break
                    if decomp is not None:
                        dec_pair = _decode_bytes_to_text(decomp)
                        if dec_pair is not None:
                            dec_text, enc_used = dec_pair
                            _add_child(
                                parent=curr_node,
                                child_text=dec_text,
                                technique="base64_deflate_decode",
                                parameters={"encoding": enc_used},
                                is_reconstructed=False,
                            )
                            if span_str != text.strip():
                                spliced = _splice_reconstructed(
                                    text, m_b64.start(), m_b64.end(), dec_text
                                )
                                _add_child(
                                    parent=curr_node,
                                    child_text=spliced,
                                    technique="base64_deflate_decode",
                                    parameters={"encoding": enc_used, "reconstructed": True},
                                    is_reconstructed=True,
                                )
                            break

            if explicit_xor_keys:
                xor_matched = False
                for xk in explicit_xor_keys:
                    xored_bytes = bytes(b ^ xk for b in raw_b64)
                    dec_pair = _decode_bytes_to_text(xored_bytes)
                    if dec_pair is not None:
                        dec_text, enc_used = dec_pair
                        xor_matched = True
                        _add_child(
                            parent=curr_node,
                            child_text=dec_text,
                            technique="xor_explicit",
                            parameters={"key": hex(xk), "encoding": enc_used},
                            is_reconstructed=False,
                        )
                        if span_str != text.strip():
                            spliced = _splice_reconstructed(
                                text, m_b64.start(), m_b64.end(), dec_text
                            )
                            _add_child(
                                parent=curr_node,
                                child_text=spliced,
                                technique="xor_explicit",
                                parameters={
                                    "key": hex(xk),
                                    "encoding": enc_used,
                                    "reconstructed": True,
                                },
                                is_reconstructed=True,
                            )
                if xor_matched:
                    continue

            dec_pair = _decode_bytes_to_text(raw_b64)
            if dec_pair is not None:
                dec_text, enc_used = dec_pair
                tech_name = "base64_utf16le" if enc_used == "utf-16le" else "base64_utf8"
                _add_child(
                    parent=curr_node,
                    child_text=dec_text,
                    technique=tech_name,
                    parameters={"encoding": enc_used},
                    is_reconstructed=False,
                )
                if span_str != text.strip():
                    spliced = _splice_reconstructed(
                        text, m_b64.start(), m_b64.end(), dec_text
                    )
                    _add_child(
                        parent=curr_node,
                        child_text=spliced,
                        technique=tech_name,
                        parameters={"encoding": enc_used, "reconstructed": True},
                        is_reconstructed=True,
                    )
            else:
                unresolved_binary_blobs.append((curr_node, m_b64.start(), m_b64.end(), raw_b64))

    current_parent_ids = {e.parent_id for e in edges}
    for parent_node, sp_start, sp_end, blob in unresolved_binary_blobs:
        if parent_node.node_id not in current_parent_ids and len(nodes) < cfg.max_nodes:
            bf_res = _try_fallback_xor_bruteforce(blob)
            if bf_res is not None:
                bf_text, bf_key = bf_res
                _add_child(
                    parent=parent_node,
                    child_text=bf_text,
                    technique="xor_bruteforce",
                    parameters={"key": hex(bf_key)},
                    is_reconstructed=False,
                )
                spliced = _splice_reconstructed(parent_node.text, sp_start, sp_end, bf_text)
                _add_child(
                    parent=parent_node,
                    child_text=spliced,
                    technique="xor_bruteforce",
                    parameters={"key": hex(bf_key), "reconstructed": True},
                    is_reconstructed=True,
                )

    dag = UnpackingDAG(
        root_id=root_node.node_id,
        nodes=nodes,
        edges=edges,
        primary_leaf_id=root_node.node_id,
        truncated=truncated,
        warnings=warnings,
    )
    leaves = dag.get_leaf_nodes()
    best_leaf = max(leaves, key=_rank_leaf_node)
    dag.primary_leaf_id = best_leaf.node_id
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
        harvested_iocs = extract_iocs(dag)

        return TriageVerdict(
            source_id=source_id,
            original_command=raw_cmd,
            primary_unmasked_payload=primary_node.text,
            dag=dag,
            provenance_chain=dag.get_provenance_chain(dag.primary_leaf_id),
            leaf_payloads=leaves,
            iocs=harvested_iocs,
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

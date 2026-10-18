"""MITRE ATT&CK behavioral and LOLBin intent classifier and risk scorer."""

from __future__ import annotations

import re
from dataclasses import dataclass

from cmd_unmask.models import BehavioralMatch, ExtractedIOC, Severity, UnpackingDAG


@dataclass(frozen=True)
class _BehavioralRule:
    rule_id: str
    name: str
    mitre_id: str
    tactic: str
    weight: int
    pattern: re.Pattern[str]


_NODE_RULES: tuple[_BehavioralRule, ...] = (
    _BehavioralRule(
        rule_id="PS_SUSPICIOUS_EXEC",
        name="PowerShell Suspicious Execution / Cradle",
        mitre_id="T1059.001",
        tactic="Execution",
        weight=25,
        pattern=re.compile(
            r"(?:\b(?:iex|invoke-expression)\b|-(?:e|en|enc|enco|encod|encode|encoded|encodedcommand)\b|-(?:w|windowstyle)\s+hidden\b|frombase64string|io\.compression\.(?:gzip|deflate)stream)",
            re.IGNORECASE,
        ),
    ),
    _BehavioralRule(
        rule_id="CMD_SHELL_EXEC",
        name="Windows Command Shell Execution",
        mitre_id="T1059.003",
        tactic="Execution",
        weight=15,
        pattern=re.compile(
            r"\bcmd(?:\.exe)?\s+/[ck]\b",
            re.IGNORECASE,
        ),
    ),
    _BehavioralRule(
        rule_id="UNIX_SHELL_EXEC",
        name="Unix Shell Command Execution",
        mitre_id="T1059.004",
        tactic="Execution",
        weight=20,
        pattern=re.compile(
            r"(?:/bin/(?:ba)?sh\b|\b(?:ba)?sh\s+-c\b|\|\s*(?:ba)?sh\b)",
            re.IGNORECASE,
        ),
    ),
    _BehavioralRule(
        rule_id="INGRESS_TOOL_TRANSFER",
        name="Ingress Tool Transfer / Remote Download Cradle",
        mitre_id="T1105",
        tactic="Command and Control",
        weight=35,
        pattern=re.compile(
            r"(?:\b(?:downloadstring|downloadfile|downloaddata|invoke-webrequest|invoke-restmethod|start-bitstransfer|net\.webclient)\b|\bcertutil(?:\.exe)?\b[^;|\n]*?-urlcache\b|\bbitsadmin(?:\.exe)?\b[^;|\n]*?/transfer\b|\b(?:curl|wget)\b[^;|\n]*?https?://)",
            re.IGNORECASE,
        ),
    ),
    _BehavioralRule(
        rule_id="LOLBIN_MSHTA",
        name="Mshta Proxy Execution",
        mitre_id="T1218.005",
        tactic="Defense Evasion",
        weight=35,
        pattern=re.compile(
            r"\bmshta(?:\.exe)?\b\s+(?:vbscript:|javascript:|https?://|\S+\.hta\b)",
            re.IGNORECASE,
        ),
    ),
    _BehavioralRule(
        rule_id="LOLBIN_REGSVR32",
        name="Regsvr32 Squiblydoo / Proxy Execution",
        mitre_id="T1218.010",
        tactic="Defense Evasion",
        weight=35,
        pattern=re.compile(
            r"\bregsvr32(?:\.exe)?\b[^;|\n]*?(?:/i:https?://|scrobj\.dll\b|/s\b.*?/u\b)",
            re.IGNORECASE,
        ),
    ),
    _BehavioralRule(
        rule_id="LOLBIN_RUNDLL32",
        name="Rundll32 Proxy Execution",
        mitre_id="T1218.011",
        tactic="Defense Evasion",
        weight=30,
        pattern=re.compile(
            r"\brundll32(?:\.exe)?\b\s+[^;|\n]+",
            re.IGNORECASE,
        ),
    ),
    _BehavioralRule(
        rule_id="LOLBIN_MSIEXEC",
        name="Msiexec Remote/Quiet Package Execution",
        mitre_id="T1218.007",
        tactic="Defense Evasion",
        weight=35,
        pattern=re.compile(
            r"\bmsiexec(?:\.exe)?\b[^;|\n]*?(?:/q\b|/i\s+https?://|/i\s+\\\\)",
            re.IGNORECASE,
        ),
    ),
    _BehavioralRule(
        rule_id="CERTUTIL_DECODE",
        name="Certutil File Decode",
        mitre_id="T1140",
        tactic="Defense Evasion",
        weight=30,
        pattern=re.compile(
            r"\bcertutil(?:\.exe)?\b[^;|\n]*?-decode(?:hex)?\b",
            re.IGNORECASE,
        ),
    ),
    _BehavioralRule(
        rule_id="AMSI_DEFENDER_TAMPER",
        name="Impair Defenses: AMSI / Windows Defender Tampering",
        mitre_id="T1562.001",
        tactic="Defense Evasion",
        weight=40,
        pattern=re.compile(
            r"\b(?:amsiutils|amsiinitfailed|set-mppreference|disablerealtimemonitoring|disablebehaviormonitoring|disableioavprotection)\b",
            re.IGNORECASE,
        ),
    ),
    _BehavioralRule(
        rule_id="CREDENTIAL_DUMPING",
        name="OS Credential Dumping (LSASS / SAM)",
        mitre_id="T1003",
        tactic="Credential Access",
        weight=45,
        pattern=re.compile(
            r"(?:\b(?:comsvcs\.dll[^;|\n]*?minidump|sekurlsa|mimikatz|lsass\.dmp)\b|\breg(?:\.exe)?\s+save\s+hklm\\(?:sam|system|security)\b)",
            re.IGNORECASE,
        ),
    ),
    _BehavioralRule(
        rule_id="SCHEDULED_TASK",
        name="Scheduled Task Persistence",
        mitre_id="T1053.005",
        tactic="Persistence",
        weight=30,
        pattern=re.compile(
            r"\b(?:schtasks(?:\.exe)?\s+/create|register-scheduledtask)\b",
            re.IGNORECASE,
        ),
    ),
    _BehavioralRule(
        rule_id="REGISTRY_RUN_KEY",
        name="Registry Run Keys Persistence",
        mitre_id="T1547.001",
        tactic="Persistence",
        weight=30,
        pattern=re.compile(
            r"currentversion\\run(?:once)?\b",
            re.IGNORECASE,
        ),
    ),
)


def classify_node_text(text: str, source_node_id: str = "node_0") -> list[BehavioralMatch]:
    """Evaluate a single PayloadNode text against behavioral and LOLBin rules."""
    if not text:
        return []
    matches: list[BehavioralMatch] = []
    for rule in _NODE_RULES:
        m = rule.pattern.search(text)
        if m:
            evidence = m.group(0).strip()
            if len(evidence) > 120:
                evidence = evidence[:117] + "..."
            matches.append(
                BehavioralMatch(
                    rule_id=rule.rule_id,
                    name=rule.name,
                    mitre_id=rule.mitre_id,
                    tactic=rule.tactic,
                    weight=rule.weight,
                    evidence=evidence,
                    source_node_id=source_node_id,
                )
            )
    return matches


def classify_dag(dag: UnpackingDAG) -> list[BehavioralMatch]:
    """Classify obfuscation mechanics and payload behaviors across the entire UnpackingDAG."""
    matches: list[BehavioralMatch] = []
    seen_rules: set[str] = set()

    # Stage 1: Obfuscation and decoding mechanics from DAG edges
    for edge in dag.edges:
        if edge.technique in ("shell_normalizer", "expression_resolver"):
            if "OBF_COMMAND" not in seen_rules:
                seen_rules.add("OBF_COMMAND")
                matches.append(
                    BehavioralMatch(
                        rule_id="OBF_COMMAND",
                        name="Command Obfuscation (Shell/Expression Layer)",
                        mitre_id="T1027.010",
                        tactic="Defense Evasion",
                        weight=18,
                        evidence=f"{edge.parent_id} -> {edge.child_id} via {edge.technique}",
                        source_node_id=edge.child_id,
                    )
                )
        elif edge.technique != "root":
            if "OBF_DECODE" not in seen_rules:
                seen_rules.add("OBF_DECODE")
                matches.append(
                    BehavioralMatch(
                        rule_id="OBF_DECODE",
                        name="Deobfuscate/Decode Payload Layer",
                        mitre_id="T1140",
                        tactic="Defense Evasion",
                        weight=22,
                        evidence=f"{edge.parent_id} -> {edge.child_id} via {edge.technique}",
                        source_node_id=edge.child_id,
                    )
                )

    # Stage 2: Behavioral / LOLBin rules across all Payload Nodes
    for node_id, node in dag.nodes.items():
        for hit in classify_node_text(node.text, source_node_id=node_id):
            if hit.rule_id not in seen_rules:
                seen_rules.add(hit.rule_id)
                matches.append(hit)

    return matches


def score_verdict(
    dag: UnpackingDAG,
    behavioral_matches: list[BehavioralMatch],
    iocs: list[ExtractedIOC],
) -> tuple[int, Severity]:
    """Compute deterministic Risk Score (0-100) and Severity from behavioral hits, IOCs, and DAG depth."""
    chain = dag.get_provenance_chain(dag.primary_leaf_id)
    obfuscation_layers = len(chain) or (1 if dag.edges else 0)

    if not behavioral_matches and obfuscation_layers == 0:
        return 0, Severity.BENIGN

    base_score = sum(m.weight for m in behavioral_matches)
    if iocs and (behavioral_matches or obfuscation_layers > 0):
        base_score += min(15, 5 * len(iocs))

    if obfuscation_layers > 0 and base_score == 0:
        base_score = 20 * obfuscation_layers

    multiplier = 1.0 + min(0.60, 0.15 * obfuscation_layers)
    final_score = min(100, max(1, round(base_score * multiplier)))

    if final_score >= 85:
        severity = Severity.CRITICAL
    elif final_score >= 60:
        severity = Severity.HIGH
    elif final_score >= 35:
        severity = Severity.MEDIUM
    else:
        severity = Severity.LOW

    return final_score, severity

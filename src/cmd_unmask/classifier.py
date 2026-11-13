"""MITRE ATT&CK behavioral and LOLBin intent classifier and risk scorer."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from cmd_unmask.models import BehavioralMatch, ExtractedIOC, Severity, UnpackingDAG

# Known cloud provider instance metadata service address (IMDSv1 / IMDSv2)
CLOUD_METADATA_ADDRESS: str = "169.254.169.254"

# Credential-bearing cloud metadata URI path substrings:
# - AWS EC2: IAM security credentials role tokens (/latest/meta-data/iam/security-credentials/)
# - Azure IMDS: Managed Identity OAuth2 tokens (/metadata/identity/oauth2/token)
# - GCP Metadata: Service account identity/access tokens (/computeMetadata/v1/instance/service-accounts/)
CREDENTIAL_METADATA_PATHS: tuple[str, ...] = (
    "security-credentials",
    "identity/oauth2/token",
    "service-accounts",
)


def _is_link_local_host(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_link_local
    except ValueError:
        return False


def _has_non_link_local_host(iocs: list[ExtractedIOC]) -> bool:
    for ioc in iocs:
        if ioc.ioc_type == "url":
            try:
                host = urlsplit(ioc.raw_value).hostname
                if host and not _is_link_local_host(host):
                    return True
            except Exception:
                pass
        elif ioc.ioc_type == "domain":
            return True
        elif ioc.ioc_type in ("ipv4", "ipv6"):
            if not _is_link_local_host(ioc.raw_value):
                return True
    return False


def _executes_downloaded_content(text: str) -> bool:
    low = text.lower()
    if re.search(r"\b(?:iex|invoke-expression)\b", low):
        return True
    if re.search(r"\|\s*(?:iex|invoke-expression|powershell|pwsh|cmd|sh|bash)\b", low):
        return True
    if "-outfile" in low and re.search(r"(?:&|\bstart(?:-process)?\b|\binvoke-item\b|\bcmd(?:\.exe)?\s+/[ck]\b|\bpowershell(?:\.exe)?\b)", low):
        return True
    return False


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

    if CLOUD_METADATA_ADDRESS in text:
        low = text.lower()
        m_url = re.search(r"https?://169\.254\.169\.254\S*", text, re.IGNORECASE)
        ev = m_url.group(0).rstrip(",.;'\")>]") if m_url else CLOUD_METADATA_ADDRESS
        if len(ev) > 120:
            ev = ev[:117] + "..."
        if any(p in low for p in CREDENTIAL_METADATA_PATHS):
            matches.append(
                BehavioralMatch(
                    rule_id="CLOUD_METADATA_CREDENTIALS",
                    name="Cloud Metadata API Credential Access",
                    mitre_id="T1552.005",
                    tactic="Credential Access",
                    weight=35,
                    evidence=ev,
                    source_node_id=source_node_id,
                )
            )
        else:
            matches.append(
                BehavioralMatch(
                    rule_id="CLOUD_METADATA_QUERY",
                    name="Cloud Instance Metadata API Query",
                    mitre_id="T1552.005",
                    tactic="Credential Access",
                    weight=15,
                    evidence=ev,
                    source_node_id=source_node_id,
                )
            )

    return matches


_SHELL_AND_LOLBIN_CHILDREN: frozenset[str] = frozenset(
    {
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "msiexec.exe",
        "wmic.exe",
        "sh",
        "bash",
        "dash",
        "zsh",
        "ash",
    }
)


@dataclass(frozen=True)
class _SpawnMatrixEntry:
    rule_id: str
    name: str
    mitre_id: str
    tactic: str
    weight: int
    parents: frozenset[str]


_SPAWN_MATRIX: tuple[_SpawnMatrixEntry, ...] = (
    _SpawnMatrixEntry(
        rule_id="LINEAGE_OFFICE_SPAWN",
        name="Suspicious Office / Document Reader Child Process",
        mitre_id="T1566.001",
        tactic="Initial Access",
        weight=45,
        parents=frozenset(
            {
                "winword.exe",
                "excel.exe",
                "powerpnt.exe",
                "outlook.exe",
                "onenote.exe",
                "msaccess.exe",
                "mspub.exe",
                "acrord32.exe",
                "acrobat.exe",
                "foxitreader.exe",
            }
        ),
    ),
    _SpawnMatrixEntry(
        rule_id="LINEAGE_WEBSERVER_SPAWN",
        name="Web or Database Server Spawning Shell / LOLBin",
        mitre_id="T1505.003",
        tactic="Persistence",
        weight=50,
        parents=frozenset(
            {
                "w3wp.exe",
                "httpd",
                "httpd.exe",
                "nginx",
                "nginx.exe",
                "apache2",
                "tomcat.exe",
                "sqlservr.exe",
                "mysqld",
                "mysqld.exe",
                "postgres",
                "postgres.exe",
            }
        ),
    ),
    _SpawnMatrixEntry(
        rule_id="LINEAGE_WMI_SPAWN",
        name="WMI Provider Host Spawning Shell / LOLBin",
        mitre_id="T1047",
        tactic="Execution",
        weight=40,
        parents=frozenset({"wmiprvse.exe"}),
    ),
    _SpawnMatrixEntry(
        rule_id="LINEAGE_ARCHIVE_SPAWN",
        name="Archive Utility Spawning Shell / Script Engine",
        mitre_id="T1204.002",
        tactic="Execution",
        weight=35,
        parents=frozenset({"7z.exe", "7zg.exe", "winrar.exe", "rar.exe"}),
    ),
)


def _extract_basename(path_or_name: str | None) -> str:
    if not path_or_name or not isinstance(path_or_name, str):
        return ""
    cleaned = path_or_name.strip().strip("\"'")
    if not cleaned:
        return ""
    return re.split(r"[\\/]", cleaned)[-1].lower()


def _infer_child_basename(image: str | None, root_command: str) -> str:
    if image:
        base = _extract_basename(image)
        if base:
            return base
    stripped = (root_command or "").strip()
    if not stripped:
        return ""
    if stripped[0] in ('"', "'"):
        quote = stripped[0]
        end = stripped.find(quote, 1)
        token = stripped[1:end] if end != -1 else stripped[1:]
    else:
        token = stripped.split()[0]
    return _extract_basename(token)


def classify_process_lineage(
    parent_image: str | None,
    image: str | None = None,
    root_command: str = "",
) -> list[BehavioralMatch]:
    """Evaluate deterministic parent-child Spawn Matrix rules."""
    parent_base = _extract_basename(parent_image)
    if not parent_base:
        return []
    child_base = _infer_child_basename(image, root_command)
    if not child_base or child_base not in _SHELL_AND_LOLBIN_CHILDREN:
        return []

    matches: list[BehavioralMatch] = []
    for entry in _SPAWN_MATRIX:
        if parent_base in entry.parents:
            matches.append(
                BehavioralMatch(
                    rule_id=entry.rule_id,
                    name=entry.name,
                    mitre_id=entry.mitre_id,
                    tactic=entry.tactic,
                    weight=entry.weight,
                    evidence=f"{parent_base} -> {child_base}",
                    source_node_id="node_0",
                )
            )
    return matches


_STAGING_PATH_RE = re.compile(
    r"(?:"
    r"[a-zA-Z]:\\(?:users\\public|programdata|windows\\temp|perflogs|users\\[^\\/\s]+\\appdata\\local\\temp)\\[^\s\"']*"
    r"|\\(?:users\\public|programdata|windows\\temp|perflogs|appdata\\local\\temp)\\[^\s\"']*"
    r"|(?:^|[\s\"'=])(?:/tmp/|/dev/shm/|/var/tmp/)[^\s\"']*"
    r")",
    re.IGNORECASE,
)

_BENIGN_STAGING_ALLOWLIST_RE = re.compile(
    r"\\programdata\\(?:chocolatey|microsoft)\\",
    re.IGNORECASE,
)


def classify_staging_path(
    image: str | None = None,
    text: str = "",
    source_node_id: str = "node_0",
) -> list[BehavioralMatch]:
    """Detect binary execution or payload references in world-writable staging directories."""
    for candidate in (image or "", text or ""):
        if not candidate:
            continue
        for m in _STAGING_PATH_RE.finditer(candidate):
            matched_path = m.group(0).strip().lstrip("=\"'")
            if _BENIGN_STAGING_ALLOWLIST_RE.search(matched_path):
                continue
            evidence = matched_path if len(matched_path) <= 120 else matched_path[:117] + "..."
            return [
                BehavioralMatch(
                    rule_id="STAGING_PATH_ANOMALY",
                    name="Execution or Staging from World-Writable / Temp Directory",
                    mitre_id="T1036.005",
                    tactic="Defense Evasion",
                    weight=25,
                    evidence=evidence,
                    source_node_id=source_node_id,
                )
            ]
    return []


def classify_dag(
    dag: UnpackingDAG,
    iocs: list[ExtractedIOC] | None = None,
    image: str | None = None,
    parent_image: str | None = None,
    parent_command: str | None = None,
) -> list[BehavioralMatch]:
    """Classify obfuscation mechanics and payload behaviors across the entire UnpackingDAG."""
    if iocs is None:
        from cmd_unmask.ioc import extract_iocs

        iocs = extract_iocs(dag)

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

    # Stage 2b: Process Lineage Spawn Matrix
    root_node = dag.nodes.get(dag.root_id)
    root_cmd = root_node.text if root_node else ""
    for hit in classify_process_lineage(parent_image=parent_image, image=image, root_command=root_cmd):
        if hit.rule_id not in seen_rules:
            seen_rules.add(hit.rule_id)
            matches.append(hit)

    # Stage 2c: World-Writable Staging Path Anomaly (image + all DAG nodes)
    if "STAGING_PATH_ANOMALY" not in seen_rules:
        for hit in classify_staging_path(image=image, text="", source_node_id=dag.root_id):
            seen_rules.add(hit.rule_id)
            matches.append(hit)
            break
    if "STAGING_PATH_ANOMALY" not in seen_rules:
        for node_id, node in dag.nodes.items():
            for hit in classify_staging_path(image=None, text=node.text, source_node_id=node_id):
                seen_rules.add(hit.rule_id)
                matches.append(hit)
                break
            if "STAGING_PATH_ANOMALY" in seen_rules:
                break

    # Stage 3: Contextual T1105 suppression for cloud metadata queries
    if "CLOUD_METADATA_QUERY" in seen_rules or "CLOUD_METADATA_CREDENTIALS" in seen_rules:
        has_external_host = _has_non_link_local_host(iocs)
        executes_download = any(
            _executes_downloaded_content(node.text) for node in dag.nodes.values()
        )
        if not has_external_host and not executes_download:
            matches = [m for m in matches if m.mitre_id != "T1105"]

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

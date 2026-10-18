"""Full-DAG contextual IOC extractor and automatic defanging for cmd-unmask."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from cmd_unmask.models import ExtractedIOC, UnpackingDAG

_URL_RE = re.compile(
    r"\b((?:https?|ftp)://[^\s\"'<>\)\];]+)detail?"[:-7],
    re.IGNORECASE,
)

_NAMED_PIPE_RE = re.compile(
    r"(\\\\\\[^\s\\\"']+\\\\pipe\\\\[^\s\"'<>|;&,)]+)",
    re.IGNORECASE,
)

_REGISTRY_KEY_RE = re.compile(
    r"\b((?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)\\[^\s\"'<>|;&)]+)",
    re.IGNORECASE,
)

_WIN_FILEPATH_RE = re.compile(
    r"\b([A-Za-z]:\\(?:[^\s\"'<>|;&:\\]+\\)*[^\s\"'<>|;&:\\]+)"
)

_POSIX_FILEPATH_RE = re.compile(
    r"(?:(?<=^)|(?<=[\s\"'=:(;,]))(/(?:tmp|var|etc|dev/shm|home|root|opt|usr|bin|sbin|proc|mnt|srv|run)/[^\s\"'<>|;&)]+)"
)

_IPV4_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Za-z._-])((?:\d{1,3}\.){3}\d{1,3})(?![0-9A-Za-z._-])"
)

_IPV6_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Za-z:])((?:[0-9a-fA-F]{1,4}:){1,7}:?(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*)?|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4})(?![0-9A-Za-z:])"
)

_HASH_CANDIDATE_RE = re.compile(
    r"(?<![0-9a-fA-F])([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})(?![0-9a-fA-F])"
)

_DOMAIN_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Za-z._/:-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24})(?![0-9A-Za-z._-])"
)

_DOTNET_NAMESPACE_PREFIXES: tuple[str, ...] = (
    "system.",
    "microsoft.",
    "io.",
    "text.",
    "net.",
    "windows.",
    "runtime.",
    "reflection.",
    "security.",
    "diagnostics.",
    "collections.",
    "threading.",
    "linq.",
    "xml.",
    "drawing.",
    "data.",
    "web.",
    "globalization.",
    "componentmodel.",
    "configuration.",
    "management.",
    "directoryservices.",
)

_SCRIPT_OR_BINARY_EXTENSIONS: frozenset[str] = frozenset(
    {
        "exe",
        "dll",
        "ps1",
        "psm1",
        "psd1",
        "bat",
        "cmd",
        "vbs",
        "vbe",
        "js",
        "jse",
        "wsf",
        "wsh",
        "hta",
        "sh",
        "bash",
        "zsh",
        "py",
        "pyc",
        "pl",
        "rb",
        "jar",
        "msi",
        "msp",
        "scr",
        "pif",
        "cpl",
        "inf",
        "reg",
        "scf",
        "lnk",
        "txt",
        "log",
        "json",
        "jsonl",
        "xml",
        "csv",
        "yml",
        "yaml",
        "ini",
        "cfg",
        "conf",
        "tmp",
        "dat",
        "bin",
    }
)

_VALID_TLDS: frozenset[str] = frozenset(
    {
        "com",
        "net",
        "org",
        "edu",
        "gov",
        "mil",
        "int",
        "io",
        "co",
        "me",
        "us",
        "uk",
        "de",
        "ru",
        "cn",
        "fr",
        "jp",
        "kr",
        "in",
        "br",
        "au",
        "ca",
        "it",
        "nl",
        "es",
        "pl",
        "ch",
        "se",
        "no",
        "fi",
        "dk",
        "be",
        "at",
        "cz",
        "hu",
        "ro",
        "ua",
        "tr",
        "il",
        "za",
        "mx",
        "ar",
        "cl",
        "sg",
        "hk",
        "tw",
        "vn",
        "th",
        "id",
        "my",
        "ph",
        "PK",
        "ir",
        "xyz",
        "top",
        "info",
        "biz",
        "cc",
        "pw",
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "onion",
        "local",
        "lan",
        "internal",
        "example",
        "test",
        "invalid",
        "dev",
        "app",
        "cloud",
        "online",
        "site",
        "tech",
        "store",
        "shop",
        "club",
        "live",
        "pro",
        "vip",
        "win",
        "link",
        "work",
        "click",
        "stream",
        "download",
        "host",
        "space",
        "website",
        "press",
        "fun",
        "icu",
        "buzz",
        "monster",
        "cyou",
        "cfd",
        "sbs",
        "quest",
        "rest",
        "bar",
        "best",
        "uno",
        "asia",
        "mobi",
        "name",
    }
)


def defang_ioc(ioc_type: str, raw_value: str) -> str:
    """Format a network/URL indicator into a safe Defanged IOC string."""
    if ioc_type == "url":
        try:
            parts = urlsplit(raw_value)
            scheme_low = parts.scheme.lower()
            if scheme_low == "http":
                defanged_scheme = "hxxp"
            elif scheme_low == "https":
                defanged_scheme = "hxxps"
            elif scheme_low == "ftp":
                defanged_scheme = "fxp"
            else:
                defanged_scheme = parts.scheme

            netloc = parts.netloc
            if ":" in netloc and not netloc.endswith("]"):
                host_part, port_part = netloc.rsplit(":", 1)
                defanged_netloc = f"{host_part.replace('.', '[.]')}[:]{port_part}"
            else:
                defanged_netloc = netloc.replace(".", "[.]")

            return urlunsplit(
                (defanged_scheme, defanged_netloc, parts.path, parts.query, parts.fragment)
            )
        except Exception:
            return (
                raw_value.replace("http://", "hxxp://")
                .replace("https://", "hxxps://")
                .replace(".", "[.]")
            )

    if ioc_type in ("ipv4", "domain"):
        return raw_value.replace(".", "[.]")

    if ioc_type == "ipv6":
        return raw_value.replace(":", "[:]")

    return raw_value


def _overlaps_spans(start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    return any(not (end <= s_start or start >= s_end) for s_start, s_end in spans)


def _is_likely_ascii_hex_blob(hex_token: str) -> bool:
    """Return True if a hex string decodes entirely to printable ASCII characters."""
    try:
        raw = bytes.fromhex(hex_token)
    except ValueError:
        return False
    if not raw:
        return False
    printable = sum(1 for b in raw if 32 <= b <= 126 or b in (9, 10, 13))
    return (printable / len(raw)) >= 0.90


def _is_valid_standalone_domain(candidate: str, full_text: str, start: int, end: int) -> bool:
    """Validate whether a dotted token is a true standalone domain and not a .NET namespace or filename."""
    low = candidate.lower()

    # Reject .NET / PowerShell type accelerators or bracketed namespaces: [System.Net.WebClient]
    prefix_char = full_text[start - 1] if start > 0 else ""
    suffix_char = full_text[end] if end < len(full_text) else ""
    if prefix_char == "[" or suffix_char == "]" or full_text[end : end + 2] == "::":
        return False

    # Reject if preceded by a dot or variable sigil ($env.foo or .Replace)
    if prefix_char in ("$", "@"):
        return False

    if low.startswith(_DOTNET_NAMESPACE_PREFIXES):
        return False

    parts = low.split(".")
    if len(parts) < 2:
        return False
    tld = parts[-1]
    if tld in _SCRIPT_OR_BINARY_EXTENSIONS:
        return False
    if tld not in _VALID_TLDS:
        return False

    # Reject if all labels are capitalized CamelCase typical of .NET classes (e.g. Net.WebClient)
    orig_parts = candidate.split(".")
    if all(p and p[0].isupper() and any(c.islower() for c in p[1:]) for p in orig_parts):
        return False

    return True


def extract_iocs_from_text(
    text: str,
    source_node_id: str = "node_0",
    decoded_hex_blobs: set[str] | None = None,
) -> list[ExtractedIOC]:
    """Extract validated IOCs from a single text string."""
    if not text:
        return []

    results: list[ExtractedIOC] = []
    occupied_spans: list[tuple[int, int]] = []
    hex_skip = {h.lower() for h in (decoded_hex_blobs or set())}

    # 1. URLs
    for m in _URL_RE.finditer(text):
        raw_url = m.group(1).rstrip(",.;'\")>]")
        end_pos = m.start(1) + len(raw_url)
        occupied_spans.append((m.start(1), end_pos))
        results.append(
            ExtractedIOC(
                ioc_type="url",
                raw_value=raw_url,
                defanged_value=defang_ioc("url", raw_url),
                source_node_id=source_node_id,
            )
        )

    # 2. Named Pipes (before filepaths)
    for m in _NAMED_PIPE_RE.finditer(text):
        if _overlaps_spans(m.start(1), m.end(1), occupied_spans):
            continue
        raw_pipe = m.group(1).rstrip(",.;'\")")
        occupied_spans.append((m.start(1), m.start(1) + len(raw_pipe)))
        results.append(
            ExtractedIOC(
                ioc_type="named_pipe",
                raw_value=raw_pipe,
                defanged_value=defang_ioc("named_pipe", raw_pipe),
                source_node_id=source_node_id,
            )
        )

    # 3. Registry Keys
    for m in _REGISTRY_KEY_RE.finditer(text):
        if _overlaps_spans(m.start(1), m.end(1), occupied_spans):
            continue
        raw_reg = m.group(1).rstrip(",.;'\")")
        occupied_spans.append((m.start(1), m.start(1) + len(raw_reg)))
        results.append(
            ExtractedIOC(
                ioc_type="registry_key",
                raw_value=raw_reg,
                defanged_value=defang_ioc("registry_key", raw_reg),
                source_node_id=source_node_id,
            )
        )

    # 4. Windows & POSIX Filepaths
    for m in _WIN_FILEPATH_RE.finditer(text):
        if _overlaps_spans(m.start(1), m.end(1), occupied_spans):
            continue
        raw_fp = m.group(1).rstrip(",.;'\")")
        occupied_spans.append((m.start(1), m.start(1) + len(raw_fp)))
        results.append(
            ExtractedIOC(
                ioc_type="filepath",
                raw_value=raw_fp,
                defanged_value=defang_ioc("filepath", raw_fp),
                source_node_id=source_node_id,
            )
        )

    for m in _POSIX_FILEPATH_RE.finditer(text):
        if _overlaps_spans(m.start(1), m.end(1), occupied_spans):
            continue
        raw_fp = m.group(1).rstrip(",.;'\")")
        occupied_spans.append((m.start(1), m.start(1) + len(raw_fp)))
        results.append(
            ExtractedIOC(
                ioc_type="filepath",
                raw_value=raw_fp,
                defanged_value=defang_ioc("filepath", raw_fp),
                source_node_id=source_node_id,
            )
        )

    # 5. IPv4 Addresses
    for m in _IPV4_CANDIDATE_RE.finditer(text):
        if _overlaps_spans(m.start(1), m.end(1), occupied_spans):
            continue
        cand = m.group(1)
        try:
            ipaddress.IPv4Address(cand)
        except ValueError:
            continue
        occupied_spans.append((m.start(1), m.end(1)))
        results.append(
            ExtractedIOC(
                ioc_type="ipv4",
                raw_value=cand,
                defanged_value=defang_ioc("ipv4", cand),
                source_node_id=source_node_id,
            )
        )

    # 6. IPv6 Addresses
    for m in _IPV6_CANDIDATE_RE.finditer(text):
        if _overlaps_spans(m.start(1), m.end(1), occupied_spans):
            continue
        cand = m.group(1)
        try:
            ipaddress.IPv6Address(cand)
        except ValueError:
            continue
        occupied_spans.append((m.start(1), m.end(1)))
        results.append(
            ExtractedIOC(
                ioc_type="ipv6",
                raw_value=cand,
                defanged_value=defang_ioc("ipv6", cand),
                source_node_id=source_node_id,
            )
        )

    # 7. Cryptographic Hashes (MD5 / SHA1 / SHA256)
    for m in _HASH_CANDIDATE_RE.finditer(text):
        if _overlaps_spans(m.start(1), m.end(1), occupied_spans):
            continue
        cand = m.group(1)
        cand_low = cand.lower()
        # Reject uniform repeating characters (e.g. 'a' * 32)
        if len(set(cand_low)) <= 2:
            continue
        # Reject hex blobs that were decoded as hex commands or are pure ASCII text
        if cand_low in hex_skip or _is_likely_ascii_hex_blob(cand_low):
            continue
        hlen = len(cand_low)
        htype = "hash_md5" if hlen == 32 else ("hash_sha1" if hlen == 40 else "hash_sha256")
        occupied_spans.append((m.start(1), m.end(1)))
        results.append(
            ExtractedIOC(
                ioc_type=htype,
                raw_value=cand_low,
                defanged_value=cand_low,
                source_node_id=source_node_id,
            )
        )

    # 8. Standalone Domains
    for m in _DOMAIN_CANDIDATE_RE.finditer(text):
        if _overlaps_spans(m.start(1), m.end(1), occupied_spans):
            continue
        cand = m.group(1)
        if not _is_valid_standalone_domain(cand, text, m.start(1), m.end(1)):
            continue
        occupied_spans.append((m.start(1), m.end(1)))
        results.append(
            ExtractedIOC(
                ioc_type="domain",
                raw_value=cand,
                defanged_value=defang_ioc("domain", cand),
                source_node_id=source_node_id,
            )
        )

    return results


def extract_iocs(dag: UnpackingDAG) -> list[ExtractedIOC]:
    """Harvest and deduplicate contextual IOCs across all Payload Nodes in an UnpackingDAG."""
    # Collect any hex substrings that were decoded into child nodes via hex_decode
    decoded_hex_blobs: set[str] = set()
    for edge in dag.edges:
        if edge.technique == "hex_decode":
            child_node = dag.nodes.get(edge.child_id)
            if child_node and not edge.parameters.get("reconstructed"):
                decoded_hex_blobs.add(child_node.text.encode("utf-8", errors="ignore").hex().lower())

    all_iocs: list[ExtractedIOC] = []
    seen: set[tuple[str, str]] = set()

    for node_id, node in dag.nodes.items():
        node_iocs = extract_iocs_from_text(
            node.text,
            source_node_id=node_id,
            decoded_hex_blobs=decoded_hex_blobs,
        )
        for item in node_iocs:
            dedup_key = (item.ioc_type, item.raw_value.lower() if item.ioc_type in ("domain", "ipv4", "ipv6", "hash_md5", "hash_sha1", "hash_sha256") else item.raw_value)
            if dedup_key not in seen:
                seen.add(dedup_key)
                all_iocs.append(item)

    return all_iocs

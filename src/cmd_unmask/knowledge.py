"""Deterministic Domain Knowledge Base for LOLBins, execution flags, masquerading, and network targets."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class BinaryProfile:
    """Static operational profile of a Windows/Linux LOLBin or system utility."""

    name: str
    platform: str
    legitimate_purpose: str
    abuse_vector: str
    mitre_ids: tuple[str, ...]


_RAW_PROFILES: tuple[BinaryProfile, ...] = (
    # Windows LOLBins & System Utilities (31)
    BinaryProfile("powershell.exe", "windows", "Task automation and configuration shell", "In-memory script execution, encoded payloads, download cradles", ("T1059.001", "T1105")),
    BinaryProfile("pwsh.exe", "windows", "Cross-platform PowerShell 7+ host", "Cross-platform encoded payload execution and C2 cradles", ("T1059.001", "T1105")),
    BinaryProfile("cmd.exe", "windows", "Windows Command Prompt interpreter", "Batch/caret-obfuscated execution and LOLBin chaining", ("T1059.003",)),
    BinaryProfile("certutil.exe", "windows", "Certificate Services CLI utility", "Remote file download (-urlcache) and Base64 decode/encode", ("T1105", "T1140")),
    BinaryProfile("mshta.exe", "windows", "Microsoft HTML Application host", "Executes remote HTA/VBScript/JScript payloads", ("T1218.005",)),
    BinaryProfile("rundll32.exe", "windows", "Windows DLL host launcher", "Proxies DLL export execution and comsvcs.dll LSASS MiniDump", ("T1218.011", "T1003.001")),
    BinaryProfile("regsvr32.exe", "windows", "COM DLL registration utility", "Squiblydoo remote SCT scriptlet execution (/s /u /i:)", ("T1218.010",)),
    BinaryProfile("bitsadmin.exe", "windows", "Background Intelligent Transfer Service CLI", "Stealthy background file download and persistence jobs", ("T1197", "T1105")),
    BinaryProfile("wmic.exe", "windows", "WMI command-line interface", "Lateral process creation and remote XSL scriptlet execution", ("T1047", "T1220")),
    BinaryProfile("cscript.exe", "windows", "Console Windows Script Host", "Executes dropped VBS/JS/WSF payloads", ("T1059.005", "T1059.007")),
    BinaryProfile("wscript.exe", "windows", "GUI Windows Script Host", "Executes dropped VBS/JS/WSF payloads silently", ("T1059.005", "T1059.007")),
    BinaryProfile("msiexec.exe", "windows", "Windows Installer engine", "Quiet remote MSI package installation (/q /i http://...)", ("T1218.007",)),
    BinaryProfile("schtasks.exe", "windows", "Task Scheduler CLI", "Creates scheduled tasks for persistence or privilege escalation", ("T1053.005",)),
    BinaryProfile("sc.exe", "windows", "Service Control Manager CLI", "Creates, modifies, or stops Windows services for persistence", ("T1543.003",)),
    BinaryProfile("reg.exe", "windows", "Windows Registry CLI", "Run-key persistence, security control tampering, SAM/SYSTEM hive dump", ("T1112", "T1003.002")),
    BinaryProfile("net.exe", "windows", "Windows network & account CLI", "Local/domain user, group, and share enumeration", ("T1087", "T1069")),
    BinaryProfile("net1.exe", "windows", "Windows network helper binary", "Account/group enumeration bypassing net.exe monitoring", ("T1087", "T1069")),
    BinaryProfile("nltest.exe", "windows", "Active Directory trust/domain locator", "Domain controller and trust enumeration (/dclist, /domain_trusts)", ("T1482",)),
    BinaryProfile("whoami.exe", "windows", "Current user and privilege printer", "Post-exploitation user/privilege discovery (/priv, /all)", ("T1033",)),
    BinaryProfile("procdump.exe", "windows", "Sysinternals process dump utility", "LSASS credential memory dumping (-ma lsass.exe)", ("T1003.001",)),
    BinaryProfile("vssadmin.exe", "windows", "Volume Shadow Copy CLI", "Shadow copy deletion to inhibit ransomware recovery", ("T1490",)),
    BinaryProfile("wbadmin.exe", "windows", "Windows Backup CLI", "Deletes system backups and catalogs prior to encryption", ("T1490",)),
    BinaryProfile("bcdedit.exe", "windows", "Boot Configuration Data editor", "Disables recovery mode and boot status policies", ("T1490",)),
    BinaryProfile("wevtutil.exe", "windows", "Windows Event Log CLI", "Clears Security/System/PowerShell event logs", ("T1070.001",)),
    BinaryProfile("msbuild.exe", "windows", "Microsoft Build Engine", "Compiles and executes inline C# tasks bypassing AppLocker", ("T1127.001",)),
    BinaryProfile("installutil.exe", "windows", ".NET Installer utility", "Executes malicious .NET assemblies via Uninstall() method", ("T1218.004",)),
    BinaryProfile("regasm.exe", "windows", ".NET Assembly Registration tool", "Executes .NET COM assemblies bypassing application allowlisting", ("T1218.009",)),
    BinaryProfile("forfiles.exe", "windows", "Batch file iteration utility", "Indirect command execution (/c) to evade parent-child rules", ("T1202",)),
    BinaryProfile("cmstp.exe", "windows", "Connection Manager Profile Installer", "INF scriptlet execution and UAC bypass", ("T1218.003",)),
    BinaryProfile("hh.exe", "windows", "HTML Help executable", "Executes compiled CHM help files or remote URLs", ("T1218.001",)),
    BinaryProfile("curl.exe", "windows", "Built-in Windows HTTP transfer tool", "Downloads remote stagers or exfiltrates data over HTTP(S)", ("T1105",)),
    # Linux / Unix Utilities & Interpreters (15)
    BinaryProfile("bash", "linux", "Bourne-Again SHell", "Interactive reverse shells (/dev/tcp), base64 pipes, script execution", ("T1059.004",)),
    BinaryProfile("sh", "linux", "POSIX system shell", "Lightweight reverse shells and dropper execution", ("T1059.004",)),
    BinaryProfile("dash", "linux", "Debian Almquist Shell", "POSIX shell dropper execution", ("T1059.004",)),
    BinaryProfile("curl", "linux", "HTTP/S data transfer CLI", "Streams remote scripts directly to sh/bash (curl | sh)", ("T1105",)),
    BinaryProfile("wget", "linux", "Non-interactive network downloader", "Fetches remote payloads to /tmp or /dev/shm", ("T1105",)),
    BinaryProfile("python3", "linux", "Python 3 interpreter", "Inline socket reverse shells and PTY spawning", ("T1059.006",)),
    BinaryProfile("python", "linux", "Python interpreter", "Inline socket reverse shells and encoded one-liners", ("T1059.006",)),
    BinaryProfile("perl", "linux", "Perl interpreter", "Socket reverse shells and inline payload execution", ("T1059",)),
    BinaryProfile("nc", "linux", "Netcat networking utility", "Reverse/bind shells (-e /bin/sh) and port scanning", ("T1059.004", "T1095")),
    BinaryProfile("ncat", "linux", "Nmap Netcat utility", "Encrypted or plain reverse/bind shells", ("T1059.004", "T1095")),
    BinaryProfile("socat", "linux", "Multipurpose relay tool", "Interactive PTY reverse shells over TCP/TLS", ("T1095",)),
    BinaryProfile("chmod", "linux", "File permission modifier", "Marks downloaded payloads executable (chmod +x)", ("T1222.002",)),
    BinaryProfile("nohup", "linux", "Hangup-immune process launcher", "Detaches malicious background implants from terminal session", ("T1059.004",)),
    BinaryProfile("crontab", "linux", "Cron job scheduler", "Installs recurring persistence tasks", ("T1053.003",)),
    BinaryProfile("systemctl", "linux", "Systemd service controller", "Creates/enables malicious systemd unit persistence", ("T1543.002",)),
)

LOLBIN_PROFILES: dict[str, BinaryProfile] = {p.name: p for p in _RAW_PROFILES}

_FLAG_SEMANTICS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?:^|\s)-(?:e|enc|encodedcommand)\b", re.IGNORECASE), "-enc / -EncodedCommand: Executes UTF-16LE Base64-encoded PowerShell payload"),
    (re.compile(r"(?:^|\s)-(?:nop|noprofile)\b", re.IGNORECASE), "-NoP / -NoProfile: Skips PowerShell user profile scripts for faster/stealthier run"),
    (re.compile(r"(?:^|\s)-(?:w|windowstyle)\s+hidden\b", re.IGNORECASE), "-W Hidden / -WindowStyle Hidden: Hides console window from desktop user"),
    (re.compile(r"(?:^|\s)-(?:ep|executionpolicy)\s+bypass\b", re.IGNORECASE), "-ep bypass: Bypasses local PowerShell script execution policy restrictions"),
    (re.compile(r"\bcomsvcs\.dll\b", re.IGNORECASE), "comsvcs.dll: Windows COM+ DLL abused with MiniDump to dump LSASS memory"),
    (re.compile(r"\bminidump\b", re.IGNORECASE), "MiniDump: Exports process memory (often LSASS) to disk for offline credential extraction"),
    (re.compile(r"(?:^|\s)-urlcache\b", re.IGNORECASE), "-urlcache: CertUtil flag abused to download remote files over HTTP(S)"),
    (re.compile(r"\bamsiinitfailed\b", re.IGNORECASE), "amsiInitFailed: In-memory AMSI bypass reflection field disabling script scanning"),
    (re.compile(r"(?:^|\s)/c\b", re.IGNORECASE), "/c: Executes command string and terminates cmd.exe"),
    (re.compile(r"(?:^|\s)/q\b", re.IGNORECASE), "/q: Quiet/unattended execution mode (e.g., msiexec or reg)"),
    (re.compile(r"/dev/tcp/", re.IGNORECASE), "/dev/tcp/: Bash built-in pseudo-device for raw TCP socket reverse shells"),
)

_CLOUD_METADATA_HOSTS: frozenset[str] = frozenset(
    {"169.254.169.254", "metadata.google.internal", "metadata.azure.internal", "100.100.100.200"}
)

_TRUSTED_VENDOR_ROOTS: tuple[str, ...] = (
    "microsoft.com",
    "windowsupdate.com",
    "windows.net",
    "powershellgallery.com",
    "nuget.org",
    "github.com",
    "githubusercontent.com",
    "chocolatey.org",
    "ubuntu.com",
    "debian.org",
    "redhat.com",
    "pypi.org",
)


def _basename(binary_or_path: str) -> str:
    cleaned = binary_or_path.strip().strip("\"'")
    if not cleaned:
        return ""
    return cleaned.replace("\\", "/").rsplit("/", 1)[-1].lower()


def lookup_binary_profile(binary_or_path: str) -> BinaryProfile | None:
    """Return static BinaryProfile for a binary name or full path, or None if unknown."""
    base = _basename(binary_or_path)
    if not base:
        return None
    return LOLBIN_PROFILES.get(base)


def explain_execution_flags(command: str) -> list[str]:
    """Return deterministic human-readable explanations for recognized execution flags in command."""
    if not command:
        return []
    explanations: list[str] = []
    for pattern, desc in _FLAG_SEMANTICS:
        if pattern.search(command):
            explanations.append(desc)
    return explanations


def _extract_host(value: str, ioc_type: str) -> str:
    raw = value.strip()
    if ioc_type == "url" or "://" in raw:
        try:
            parsed = urlparse(raw)
            return (parsed.hostname or "").lower()
        except Exception:
            return ""
    host = raw.lower()
    if ":" in host and host.count(":") == 1:
        host = host.split(":", 1)[0]
    return host.strip("[]")


_RFC1918_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)


def classify_network_target(value: str, ioc_type: str = "") -> str:
    """Classify an IP, URL, or domain as cloud_metadata, loopback, private_rfc1918, trusted_vendor, or public_external."""
    host = _extract_host(value, ioc_type)
    if not host:
        return "public_external"

    if host in _CLOUD_METADATA_HOSTS:
        return "cloud_metadata"

    try:
        ip_obj = ipaddress.ip_address(host)
        if str(ip_obj) == "169.254.169.254" or ip_obj.is_link_local:
            return "cloud_metadata"
        if ip_obj.is_loopback:
            return "loopback"
        if any(ip_obj in net for net in _RFC1918_NETS):
            return "private_rfc1918"
        return "public_external"
    except ValueError:
        pass

    for root in _TRUSTED_VENDOR_ROOTS:
        if host == root or host.endswith("." + root):
            return "trusted_vendor"

    return "public_external"

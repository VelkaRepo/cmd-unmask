import unittest

from cmd_unmask.classifier import classify_dag, classify_process_lineage
from cmd_unmask.models import PayloadNode, Severity, UnpackingDAG
from cmd_unmask.unpacker import unmask_command


class TestParentChildSpawnMatrix(unittest.TestCase):
    def test_office_spawning_shell_or_lolbin(self):
        hits = classify_process_lineage(
            parent_image="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            image="C:\\Windows\\System32\\cmd.exe",
            root_command="cmd.exe /c whoami",
        )
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].rule_id, "LINEAGE_OFFICE_SPAWN")
        self.assertEqual(hits[0].mitre_id, "T1566.001")
        self.assertGreaterEqual(hits[0].weight, 40)

        verdict = unmask_command(
            "powershell.exe -NoP -Command Get-Date",
            parent_image="excel.exe",
        )
        self.assertTrue(any(m.mitre_id == "T1566.001" for m in verdict.behavioral_matches))
        self.assertGreaterEqual(verdict.severity.rank, Severity.MEDIUM.rank)

    def test_webserver_and_db_spawning_shell(self):
        for parent in ("C:\\Windows\\System32\\inetsrv\\w3wp.exe", "/usr/sbin/nginx", "sqlservr.exe"):
            hits = classify_process_lineage(
                parent_image=parent,
                image=None,
                root_command="sh -c id" if "nginx" in parent else "cmd.exe /c whoami",
            )
            self.assertEqual(len(hits), 1, f"Failed for parent={parent}")
            self.assertEqual(hits[0].rule_id, "LINEAGE_WEBSERVER_SPAWN")
            self.assertEqual(hits[0].mitre_id, "T1505.003")

    def test_wmi_and_archive_spawning_shell(self):
        wmi_hits = classify_process_lineage(
            parent_image="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            root_command="powershell.exe -NoP",
        )
        self.assertEqual(wmi_hits[0].rule_id, "LINEAGE_WMI_SPAWN")
        self.assertEqual(wmi_hits[0].mitre_id, "T1047")

        arch_hits = classify_process_lineage(
            parent_image="C:\\Program Files\\7-Zip\\7z.exe",
            image="C:\\Windows\\System32\\mshta.exe",
            root_command="mshta.exe payload.hta",
        )
        self.assertEqual(arch_hits[0].rule_id, "LINEAGE_ARCHIVE_SPAWN")
        self.assertEqual(arch_hits[0].mitre_id, "T1204.002")

    def test_benign_parent_child_counter_examples(self):
        # 1. None parent_image -> zero lineage hits
        self.assertEqual(
            classify_process_lineage(None, "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c dir"),
            [],
        )
        # 2. explorer.exe -> cmd.exe -> zero LINEAGE_* hits
        verdict_exp = unmask_command(
            "cmd.exe",
            image="C:\\Windows\\System32\\cmd.exe",
            parent_image="C:\\Windows\\explorer.exe",
        )
        self.assertEqual(verdict_exp.severity, Severity.BENIGN)
        self.assertFalse(any(m.rule_id.startswith("LINEAGE_") for m in verdict_exp.behavioral_matches))

        # 3. services.exe -> svchost.exe -> benign
        verdict_svc = unmask_command(
            "svchost.exe -k netsvcs",
            image="C:\\Windows\\System32\\svchost.exe",
            parent_image="C:\\Windows\\System32\\services.exe",
        )
        self.assertEqual(verdict_svc.severity, Severity.BENIGN)
        self.assertEqual(verdict_svc.behavioral_matches, [])


if __name__ == "__main__":
    unittest.main()

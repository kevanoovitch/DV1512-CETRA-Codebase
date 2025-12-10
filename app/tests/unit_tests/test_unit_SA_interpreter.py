import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.backend.API_interfaces.SA_Interpret import SecureAnnex_interpretator
import app.backend.API_interfaces.SA_Interpret as mod_interp

def sample_payload():
    return {
        "manifest": {
            "result": [
                {"risk_type": "ALL_URLS_ACCESS", "description": "Has <all_urls>", "severity": 7},
                {"risk_type": "SCRIPTING_PERMISSION", "description": "Can execute scripts", "severity": 6},
                {"risk_type": "WEBREQUEST", "description": "Uses webRequest", "severity": 5},
            ]
        },
        "signatures": {
            "result": [
                {"rule": "danger.rule", "name": "Danger Rule", "meta": {"severity": "high"}},  # sev 8 -> 16 pts
                {"rule": "mild.rule",   "name": "Mild Rule",   "meta": {"severity": "low"}},   # sev 3 -> 6 pts
            ]
        },
        "urls": {
            "result": [
                {"url": "http://example.com/api", "file_path": "static/background/index.js", "domain": "evil.example"},
                {"url": "https://good.com", "file_path": "content/foo.js", "domain": "good.com"},
            ]
        },
        "analysis": {
            "result": [
                {"analysis": "Possible CSP risk and data exfil"},
                {"analysis": "Looks fine"},
            ]
        },
    }

class TestSecureAnnexInterpretor(unittest.TestCase):
    def setUp(self):
       self.tmpdir = tempfile.TemporaryDirectory()
       self.addCleanup(self.tmpdir.cleanup)
       self.outfile = Path(self.tmpdir.name) / "sa_output.json"

       self.const_patch = patch.object(mod_interp.constants, "SA_OUTPUT_FILE", str(self.outfile))
       self.const_patch.start()
       self.addClassCleanup(self.const_patch.stop)

    def write_payload(self, data):
        self.outfile.write_text(json.dumps(data), encoding="utf-8")

    def test_parsing_smoke_and_expected_findings(self):
        """basic end-to-end parse: returns findings with normalized tags"""
        self.write_payload(sample_payload())

        interp = SecureAnnex_interpretator()
        res = interp.interpret_output()

        self.assertIsInstance(res, list)
        self.assertGreater(len(res), 0)
        self.assertTrue(all(isinstance(f, mod_interp.Finding) for f in res))

        tags = {f.tag for f in res}
        self.assertEqual(len(res), len(tags))
        self.assertSetEqual(
            tags,
            {
                "all_urls_access",
                "scripting_permission",
                "webrequest",
                "http_usage",
                "csp_disabled",
                "data_exfiltration",
            },
        )

        # Spot-check a few scores/categories so the mapping remains stable.
        tag_to_score = {f.tag: f.score for f in res}
        self.assertEqual(tag_to_score["all_urls_access"], 50)
        self.assertEqual(tag_to_score["data_exfiltration"], 90)
        self.assertEqual(tag_to_score["http_usage"], 20)


    def test_empty_sections_safe_defaults(self):
        self.write_payload({
                "manifest": {"result": []},
                "signatures": {"result": []},
                "urls": {"result": []},
                "analysis": {"result": []},
        })

        interp = SecureAnnex_interpretator()
        res = interp.interpret_output()
        self.assertEqual(res, [])

    def test_manifest_dedupes_identical_risks(self):
        """Repeated manifest items should collapse into one finding instead of inflating score."""

        big_manifest = {"result": [
            {"risk_type": "ALL_URLS_ACCESS", "description": "x", "severity": 10}
            for _ in range(20)  # many high-sev items to exceed the cap
        ]}

        self.write_payload({
            "manifest": big_manifest,
            "signatures": {"result": []},
            "urls": {"result": []},
            "analysis": {"result": []},
        })

        interp = SecureAnnex_interpretator()
        res = interp.interpret_output()
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].tag, "all_urls_access")
        self.assertEqual(res[0].score, 50)

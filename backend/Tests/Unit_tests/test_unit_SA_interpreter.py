import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.API_interfaces.SA_Interpret import SecureAnnex_interpretator
import backend.API_interfaces.SA_Interpret as mod_interp

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
        """basic end-to-end parse: returns score+findings, and flags and right things"""
        self.write_payload(sample_payload())

        interp = SecureAnnex_interpretator()
        res = interp.interpret_output()

        #Structure
        self.assertIn("score", res)
        self.assertIn("findings",res)
        self.assertIsInstance(res["findings"], list)
        self.assertGreaterEqual(res["score"], 0)
        self.assertLessEqual(res["score"], 100)

        manifest = [f for f in res["findings"] if f.source == "manifest"]
        sigs = [f for f in res["findings"] if f.source == "signatures"]
        urls = [f for f in res["findings"] if f.source == "urls"]
        analysis = [f for f in res["findings"] if f.source == "analysis"]

        rtypes = {f.risk_type for f in manifest}
        self.assertIn("SYNERGY_ALLURLS_SCRIPTING", rtypes)
        self.assertIn("SYNERGY_WEBREQ_GLOBAL", rtypes)

        # Signatures severity mapping -> points (high => sev 8 => 16 pts with factor=2)
        self.assertTrue(any(f.severity == 8 and f.points == 16 for f in sigs))

        # URLs: plaintext + external background domain
        url_types = {f.risk_type for f in urls}
        self.assertIn("PLAINTEXT_URL", url_types)
        self.assertIn("EXTERNAL_CONTROL_DOMAIN", url_types)

        #Analysis: keyword flags 
        self.assertTrue(analysis)

    def test_empty_sections_safe_defaults(self):
        self.write_payload({
                "manifest": {"result": []},
                "signatures": {"result": []},
                "urls": {"result": []},
                "analysis": {"result": []},
        })

        interp = SecureAnnex_interpretator()
        res = interp.interpret_output()
        self.assertEqual(res["score"],0)
        self.assertEqual(res["findings"], [])

    def test_scoring_caps_manifest(self):
        """Make manifest alone huge and verify the per-section cap (60) is applied."""

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
        # sev => 10 10*factor(5) = 50 pts per finding, but capped at 60 for manifest
        self.assertEqual(res["score"], 60)


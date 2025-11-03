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
        """basic end-to-end parse: returns score+findings, and flags and right things"""
        self.write_payload(sample_payload())

        interp = SecureAnnex_interpretator()
        res = interp.interpret_output()

        # Structure

        for key in ("score","urls", "descriptions", "risk_types"):
            self.assertIn(key,res)
        self.assertIsInstance(res["urls"], list)
        self.assertIsInstance(res["descriptions"], list)
        self.assertIsInstance(res["risk_types"], list)
        self.assertIsInstance(res["score"], int)
        self.assertIsInstance(res["score"],int)

        rtypes = set(res["risk_types"])
        self.assertIn("ALL_URLS_ACCESS", rtypes)
        self.assertIn("SCRIPTING_PERMISSION", rtypes)
        self.assertIn("WEBREQUEST", rtypes)

        descs = res["descriptions"]
        self.assertTrue(any("Scripting + <all_urls>" in d for d in descs))
        self.assertTrue(any("webRequest + broad URL scope" in d for d in descs))

        self.assertTrue(any("Signature matched:" in d for d in descs))

        self.assertTrue(any("Signature matched:" in d for d in descs))

        self.assertTrue(any(("CSP Risk" in d) or ("exfil" in d.lower()) for d in descs))

        self.assertTrue(res["urls"])
        self.assertTrue(any("http://example.com/api" in u for u in res["urls"]))
        self.assertTrue(any("static/background/index.js" in u for u in res["urls"]))

        self.assertEqual(res["score"],100)


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
        self.assertEqual(res.get("descriptions"), [])
        self.assertEqual(res.get("urls"), [])
        self.assertEqual(res.get("risk_types"), [])

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


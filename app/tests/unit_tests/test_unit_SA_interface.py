from unittest import TestCase
from unittest.mock import patch
from pathlib import Path
import json, tempfile
from types import SimpleNamespace
from requests import RequestException

from app.backend.API_interfaces.SA_interface import Interface_Secure_Annex 
import app.backend.API_interfaces.SA_interface as mod_iface

#Testing perform_scan()
class TestPerformScan(TestCase):
    """
    Will test Secure Annex by mocking output in a tempfile to limit api queries
    """
    @patch.object(mod_iface.config, "DEV_MODE", False)
    def test_perform_scan_nondev_aggregates_and_writes(self):
        sa = Interface_Secure_Annex()
        with patch.object(sa, "fetch_manifest", return_value={"m":1}), \
             patch.object(sa, "fetch_vulnerabilities", return_value={"v":1}), \
             patch.object(sa, "fetch_signatures", return_value={"s": 1}), \
             patch.object(sa, "fetch_urls", return_value={"u":1}), \
             patch.object(sa, "fetch_analysis", return_value={"a": 1}): 
            
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
            out = Path(tmp.name); tmp.close()
            sa.perform_scan("ext", out)
        
        data = json.loads(out.read_text())
        assert data == {
            "manifest": {"m":1},
            "vulnerabilities": {"v":1},
            "signatures": {"s": 1},
            "urls": {"u": 1},
            "analysis": {"a": 1},
        }         


# Test fetch_resource()
class TestFetchResources(TestCase):
    def test_json_path(self):
        sa = Interface_Secure_Annex()
        resp = SimpleNamespace(
            status_code = 200,
            json=lambda: {"ok": True},
            test="ignored",
            raise_for_status=lambda: None,
        )
        with patch.object(mod_iface.requests, "get", return_value=resp):
            assert sa.fetch_resource("x", "/manifest") == {"ok": True}
        
    def test_text_fallback(self):
        sa = Interface_Secure_Annex()
        def bad_json(): raise ValueError("not json")
        resp = SimpleNamespace(
            status_code=200,
            json=bad_json,  
            text="raw",
            raise_for_status=lambda: None,
        )
        with patch.object(mod_iface.requests, "get", return_value=resp):
            assert sa.fetch_resource("x", "/manifest") == "raw"

    def test_error_path(self):
        sa = Interface_Secure_Annex()
        def boom(*a, **k):
            raise RequestException("network down")
        with patch.object(mod_iface.requests, "get", side_effect=boom):
            assert "error" in sa.fetch_resource("x", "/manifest")



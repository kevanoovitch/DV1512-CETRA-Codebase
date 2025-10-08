import unittest
from app.backend.API_interfaces.VirusTotalInterface import scan_file

class TestVirusTotalScan(unittest.TestCase):
    def test_scan_returns_result(self):
        test_file = "app/tests/test_crx/mil.crx"
        result = scan_file(test_file, testing_mode=True)
        self.assertIsNotNone(result, "scan_file() returned None.")

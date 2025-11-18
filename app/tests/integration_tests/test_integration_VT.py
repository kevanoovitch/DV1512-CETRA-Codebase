import unittest
from app.backend.API_interfaces.VirusTotalInterface import scan_file
import os 
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VT_API_KEY")

class TestVirusTotalScan(unittest.TestCase):
    @unittest.skipUnless(API_KEY, "Skipping VirusTotal scan: API key not set.")
    def test_scan_returns_result(self):
        test_file = "app/tests/test_crx/mil.crx"
        result = scan_file(test_file)
        self.assertIsNotNone(result, "scan_file() returned None.")

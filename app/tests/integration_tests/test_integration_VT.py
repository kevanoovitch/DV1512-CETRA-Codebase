import unittest
from app.backend.API_interfaces.VirusTotalInterface import scan_file
import os 
from dotenv import load_dotenv
from app.backend.api import compute_file_hash
load_dotenv()

API_KEY = os.getenv("VT_API_KEY")

class TestVirusTotalScan(unittest.TestCase):
    @unittest.skipUnless(API_KEY, "Skipping VirusTotal scan: API key not set.")
    def test_scan_returns_result(self):
        test_file = "app/tests/test_crx/mil.crx"
        file_hash = compute_file_hash(test_file)
        result = scan_file(test_file,file_hash)
        self.assertIsNotNone(result, "scan_file() returned None.")

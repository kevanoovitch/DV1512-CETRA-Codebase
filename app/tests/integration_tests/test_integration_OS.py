import unittest
import os
from dotenv import load_dotenv
load_dotenv()
API_KEY = os.getenv("OPSWAT_API_KEY")
from app.backend.API_interfaces import OPSWAT2


API_KEY = os.getenv("OPSWAT_API_KEY")

class TestOPSWAT2Integration(unittest.TestCase):
    """
    Integrationtest for OPSWAT2.scan_file. 
    """
    TEST_FILE = "app/tests/test_crx/mil_3ErR7MX.crx" 
    @unittest.skipUnless(API_KEY, "Skipping OPSWAT scan: API key not set.")
    @unittest.skipUnless(os.path.exists(TEST_FILE), f"Skipping OPSWAT scan: Test file not found at {TEST_FILE}.")
    def test_scan_returns_result(self):
        """Tests that scan_file returns a list."""
        
        # calls MetaDefender-API:t
        result = OPSWAT2.scan_file(self.TEST_FILE)
        
        self.assertIsInstance(result, list, "Resultat from scan_file() should be a list.")
        self.assertIsNotNone(result, "scan_file() returned None.")
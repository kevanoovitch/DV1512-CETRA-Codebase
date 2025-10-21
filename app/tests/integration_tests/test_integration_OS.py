import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))


import unittest
from unittest.mock import patch, mock_open
from app.backend.API_interfaces import OPSWAT2


class TestOPSWAT2Integration(unittest.TestCase):
    """Tester att OPSWAT2.scan_file returnerar korrekt dictionary utan att kontakta API:t."""

    @patch("app.backend.API_interfaces.OPSWAT2.requests.post")
    @patch("app.backend.API_interfaces.OPSWAT2.requests.get")
    @patch("builtins.open", new_callable=mock_open, read_data=b"dummy data")
    @patch("os.path.exists", return_value=True)
    def test_scan_file_returns_expected_summary(self, mock_exists, mock_file, mock_get, mock_post):
        mock_post.return_value.json.return_value = {"data_id": "fake_id_123"}


        mock_get.return_value.json.return_value = {
            "scan_results": {
                "progress_percentage": 100,
                "scan_details": {
                    "Avira": {"scan_result_i": 0},
                    "Bitdefender": {"scan_result_i": 2},
                    "ClamAV": {"scan_result_i": 0},
                    "ESET": {"scan_result_i": 1},
                    "Kaspersky": {"scan_result_i": 0},
                    "McAfee": {"scan_result_i": 1},
                    "Sophos": {"scan_result_i": 0},
                    "AVG": {"scan_result_i": 0},
                    "TrendMicro": {"scan_result_i": 1},
                    "F-Secure": {"scan_result_i": 0},
                    "WindowsDefender": {"scan_result_i": 0},
                    "Malwarebytes": {"scan_result_i": 0},
                    "Comodo": {"scan_result_i": 0},
                    "Avast": {"scan_result_i": 0}
                }
            },
            "malware_type": ["trojan"]
        }


        result = OPSWAT2.scan_file("app/mil.crx")

        expected = {"score": 29, "malware_type": ["trojan"]}

        self.assertIsInstance(result, dict)
        self.assertEqual(result, expected)


if __name__ == "__main__":
    unittest.main()

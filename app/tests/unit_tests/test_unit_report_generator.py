
import unittest
import os
from app.backend.report_generator import calculate_final_score, generate_report, label_from_score
import tempfile
import hashlib


BASE_ARG = {
    "SA": {"score": 30, "descriptions": ["desc1"], "risk_types": ["risk1"]},
    "VT": {"score": 20, "malware_types": ["type1"]},
    "OWASP": {"score": 10, "malware_type": ["type2"]},
    "permissions": ["tabs", "cookies"],
    "file_path": "",  # will set in test
    "extension_id": "abcd1234",
}

class TestReportGenerator(unittest.TestCase):

    # Test Final score method
    def test_final_score_normal(self):
        self.assertEqual(calculate_final_score([98, 9, 2]), 36)

    def test_final_score_missing_some_args(self):
        self.assertEqual(calculate_final_score([97,3,None]), 50)
    
    def test_final_score_empty_list(self):
        self.assertEqual(calculate_final_score([]), 0)

    #Test label from score 

  

    CASES = [
        (0,  "OK / Clean"),
        (25, "OK / Clean"),
        (26, "Low suspicion"),
        (40, "Low suspicion"),
        (41, "Suspicious"),
        (55, "Suspicious"),
        (56, "Malicious"),
        (80, "Malicious"),
        (81, "Highly malicious"),
    ]

    def test_label_from_score_boundaries(self):
        for score, expected in self.CASES:
            with self.subTest(score=score):
                self.assertEqual(label_from_score(score), expected)

    # Larger test using a mock response to generate a report

    def test_report_generator_with_mock(self):
            # create real temp file
            with tempfile.NamedTemporaryFile(delete=False) as tf:
                tf.write(b"dummy-bytes")
                temp_path = tf.name
            self.addCleanup(lambda: os.path.exists(temp_path) and os.unlink(temp_path))

            arg = dict(BASE_ARG)
            arg["file_path"] = temp_path

            report = generate_report(arg)

            # expected SHA-256 of b"dummy-bytes"
            expected_hash = hashlib.sha256(b"dummy-bytes").hexdigest()

            self.assertEqual(report["score"], 20)
            # NOTE: adjust to match your production key: "description" vs "descriptions"
            self.assertEqual(report["description"], arg["SA"]["descriptions"])
            self.assertEqual(report["permissions"], arg["permissions"])
            self.assertEqual(report["risks"], arg["SA"]["risk_types"])
            self.assertEqual(report["malware_types"], arg["OWASP"]["malware_type"] + arg["VT"]["malware_types"])
            self.assertEqual(report["file_hash"], expected_hash)
            self.assertEqual(report["extension_id"], arg["extension_id"])
            self.assertEqual(report["verdict"], "OK / Clean")

        





        


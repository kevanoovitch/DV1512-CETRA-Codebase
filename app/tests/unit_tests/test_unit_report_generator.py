
import unittest
import os
import tempfile
import hashlib

from app.backend.report_generator import calculate_final_score, generate_report, label_from_score
from app.backend.utils.classlibrary import ApiResult, Finding
from app.constants import FINDINGS_API_NAMES


def make_finding(score: int, api: str, tag: str = "t", type_: str = "type", category: str = "cat") -> Finding:
    return Finding(tag=tag, type=type_, category=category, score=score, api=api)

class TestReportGenerator(unittest.TestCase):

    # Test Final score method
    def test_final_score_normal(self):
        findings = [
            make_finding(98, FINDINGS_API_NAMES["SA"]),
            make_finding(9, FINDINGS_API_NAMES["VT"]),
            make_finding(2, FINDINGS_API_NAMES["OP"]),
        ]
        self.assertEqual(calculate_final_score(findings), 36)

    def test_final_score_missing_some_args(self):
        findings = [
            make_finding(97, FINDINGS_API_NAMES["SA"]),
            make_finding(3, FINDINGS_API_NAMES["VT"]),
        ]
        self.assertEqual(calculate_final_score(findings), 50)
    
    def test_final_score_empty_list(self):
        self.assertEqual(calculate_final_score([]), -1)

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

        api_result = ApiResult()
        api_result.findings = [
            make_finding(30, FINDINGS_API_NAMES["SA"]),
            make_finding(20, FINDINGS_API_NAMES["VT"]),
            make_finding(10, FINDINGS_API_NAMES["OP"]),
        ]
        api_result.permissions = ["tabs", "cookies"]
        api_result.extension_id = "abcd1234"
        api_result.file_hash = hashlib.sha256(b"dummy-bytes").hexdigest()
        api_result.file_format.filePath = temp_path  # keep similar semantics to production

        report = generate_report(api_result)

        self.assertEqual(report["score"], 20)
        self.assertEqual(report["verdict"], "OK / Clean")
        self.assertEqual(report["permissions"], api_result.permissions)
        self.assertEqual(report["extension_id"], api_result.extension_id)
        self.assertEqual(report["file_hash"], api_result.file_hash)
        self.assertEqual(report["findings"], api_result.findings)
        self.assertIn("summary", report)
        self.assertIsInstance(report["summary"], str)
        self.assertIn("behaviour", report)

        





        

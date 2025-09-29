import unittest
from backend.API_interfaces.SA_interface import Interface_Secure_Annex


class TestSAConnection(unittest.TestCase):
    """Integration-style health check for the /updates endpoint."""

    def setUp(self):
        self.client = Interface_Secure_Annex()

    def test_sa_connection_updates(self):
        # This hits the real endpoint (non-auth). Keep it in an "integration" group if needed.
        response = self.client.fetch_resource(None, "/updates")

        self.assertIsNotNone(response, "No response from Secure Annex /updates endpoint")
        if isinstance(response, dict):
            self.assertNotIn("error", response, f"Secure Annex error: {response}")



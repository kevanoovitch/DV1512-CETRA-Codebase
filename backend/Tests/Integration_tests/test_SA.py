import pytest
import json
from backend.API_interfaces.SA_interface import Interface_Secure_Annex

#TODO: Implement theese:

#Test that it can query SA
def test_SA_connection():
    """
    This test will use a non authentication requried endpoint to health check Secure Annex
    """


    client = Interface_Secure_Annex()

    response = client.fetch_resource(None,"/updates")

    assert response is not None, "No response from Secure annex update endpoint"
    if isinstance(response,dict):
        assert "error" not in response, f"Secure Annex error: {response}"




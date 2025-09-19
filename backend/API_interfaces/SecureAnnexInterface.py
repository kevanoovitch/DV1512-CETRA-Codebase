import os, json
from dotenv import load_dotenv
import requests


class ISecureAnnex:
    def __init__(self, api_key, api_endpoint):
        load_dotenv()
        self.ApiKey = os.getenv("SA_API_KEY")
        self.ApiEndpoint = os.getenv("SA_API_ENDPOINT")
        self.HEADERS = {"x-api-key": self.ApiKey}


 
    def GetManifestRisks(self, extension):
        _extensionID = extension  # TODO: apply conversion if needed
        url = f"{self.ApiEndpoint}/manifest"

        try:
            response = requests.get(url, headers=self.HEADERS, params={"extension_id": _extensionID})
            try:
                return response.json()
            except ValueError:
                # Not JSON; return raw text
                return response.text
        except requests.RequestException as e:
            # Network or request error; return simple message
            return str(e)

   

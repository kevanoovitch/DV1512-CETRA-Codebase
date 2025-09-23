import os, json
from dotenv import load_dotenv
import requests


class ISecureAnnex:
    def __init__(self, api_key, api_endpoint):
        load_dotenv()
        self.ApiKey = os.getenv("SA_API_KEY")
        self.ApiEndpoint = os.getenv("SA_API_ENDPOINT")
        self.HEADERS = {"x-api-key": self.ApiKey}

    # <--- Getters & fetchers --->

    def fetch_resource(self,extension,endpoint):
        """
        Generic helper function to query SA

        Args: 
            string:Extension
            string: last part of the endpoint i.e "/manifest"
        """
        _extensionID = extension  # TODO: apply conversion if needed
        url = f"{self.ApiEndpoint}{endpoint}"

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

    def fetch_manifest(self, extension):
        return self.fetch_resource(extension, "/manifest")


    def fetch_vulnerabilities(self, extension):
        return self.fetch_resource(extension, "/vulnerabilities")
   
    def fetch_signatures(self, extension):
        return self.fetch_resource(extension, "/signatures")
    
    def fetch_urls(self, extension):
        return self.fetch_resource(extension, "/urls")
    
    def fetch_analysis(self, extension):
        return self.fetch_resource(extension, "/analysis")
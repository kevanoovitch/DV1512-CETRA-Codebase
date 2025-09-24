##Imports
import requests
import os
import time
from dotenv import load_dotenv

##start of code

load_dotenv()

ApiKey = os.getenv("VT_API_KEY")

if not ApiKey:
    raise ValueError

base_url = "https://www.virustotal.com/api/v3/files/upload_url"

HEADERS = { "x-apikey": ApiKey}

file_path = "root/uploaded"


def scan_file(file_path: str) -> dict:
    
    # Uploads a file to VirusTotal for scanning.
    # Returns the API response JSON (contains analysis_id).
    
    url = f"{base_url}/files"

    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f)}
        response = requests.post(url, headers=HEADERS, files=files)
    
    response.raise_for_status()
    return response.json()


def get_scan_result(analysis_id: str, interval: int = 5) -> dict:

    # Polls virus total for scan result until analysis is complete
    # Returns final report for JSON

    url = f"{base_url}/analyses/{analysis_id}"

    while True:
        response = requests.get(url, headers=HEADERS)
        response.raise_for_status()
        result = response.json()

        status = result["data"]["attributes"]["status"]
        if status == "completed":
            return result
        
        print(f"Analysis in progress... (status: {status})")
        time.sleep(interval)


if __name__ == "__main__":
    file_path = "root/uploaded"
    uploaded_response = scan_file(file_path)
    
    analysis_id = uploaded_response["data"]["id"]
    print(f"Uploaded. Analysis ID: {analysis_id}")

    report = get_scan_result
    print(f"Final report: {report}")
    
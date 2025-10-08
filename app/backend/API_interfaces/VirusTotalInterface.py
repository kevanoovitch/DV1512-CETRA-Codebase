import requests
import time
import json
from dotenv import load_dotenv
import os
from app import config

load_dotenv()

ApiKey = os.getenv("VT_API_KEY")

if not ApiKey:
    raise ValueError

base_url = "https://www.virustotal.com/api/v3/files/upload_url"

HEADERS = { "x-apikey": ApiKey}

# directory_path = "../uploaded/"


def scan_file(file_name: str, testing_mode):
    try:
        file_path = file_name if testing_mode else file_name
        
        headers = {"x-apikey": ApiKey}

        with open(file_path, "rb") as f:
            files = {"file": (file_path, f)}
            response = requests.post(
                "https://www.virustotal.com/api/v3/files",
                headers=headers,
                files=files
            )
        response.raise_for_status()
        analysis_id = response.json()["data"]["id"]

        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        
        timeout = 30
        print("loading data from Virus total")
        while timeout > 0:
            res = requests.get(analysis_url, headers=headers)
            res.raise_for_status()
            data = res.json()
            status = data["data"]["attributes"]["status"]
            if status == "completed":
                return _analyse_data(data["data"])

            time.sleep(1)
            timeout -= 1

        return None
    except Exception as e:
        print(f"[scan_file] Error: {e}")
        return None
    

def _analyse_data(result):
    data = {}
    detectedby = []
    data = {"stats":result["attributes"]["status"],}
    for engine,details in result["attributes"]["results"].items():
        if(details["category"] != "undetected" and details["category"] != "type-unsupported"):
            detectedby.append(details)
    stats = result["attributes"]["stats"]
    return  {"stats":stats, "detectedby":detectedby,"score":_calculate_malicious_score(stats)}

def _calculate_malicious_score(stats: dict) -> int:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    total = malicious + suspicious + stats.get("undetected", 0) + stats.get("harmless", 0)
    if total == 0:
        return 0

    score = (2 * malicious + 1 * suspicious) / (2 * total) * 100
    return round(score)



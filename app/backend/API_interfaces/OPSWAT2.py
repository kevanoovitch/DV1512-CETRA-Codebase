import requests
import json
import time
import os
from dotenv import load_dotenv
from app import constants

load_dotenv()
API_KEY = os.getenv("OPSWAT_API_KEY")


def scan_file(file_path):    
    """Skannar en fil med OPSWAT MetaDefender och returnerar score + malware_type som dictionary."""
   
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File '{file_path}' not found.")

    url_upload = "https://api.metadefender.com/v4/file"
    headers_upload = {
        "apikey": API_KEY,
        "Content-Type": "application/octet-stream"
    }

    with open(file_path, "rb") as f:
        payload = f.read()

    response = requests.post(url_upload, headers=headers_upload, data=payload)
    response_data = response.json()

    file_id = response_data.get("data_id") or response_data.get("file_id")
    if not file_id:
        raise Exception("Was not able to fetch file_id MetaDefender-responsen")

    url_result = f"https://api.metadefender.com/v4/file/{file_id}"
    headers_result = {"apikey": API_KEY}

    while True:
        response = requests.get(url_result, headers=headers_result)
        data = response.json()
        progress = data.get("scan_results", {}).get("progress_percentage", 0)

        if progress == 100:
            break
        time.sleep(3)


    with open(constants.SCAN_RESULT_JSON, "w") as f:
        json.dump(data, f, indent=4)


    scan_details = data["scan_results"]["scan_details"]
    total_avs = len(scan_details)
    detected_count = sum(1 for av in scan_details.values() if av.get("scan_result_i", 0) > 0)
    score = int(round(detected_count / total_avs * 100, 0)) if total_avs else 0

    malware_type = data.get("malware_type", [])
    if isinstance(malware_type, str):
        malware_type = [malware_type]


    summary = {
        "score": score,
        "malware_type": malware_type
    }

    with open(constants.SUMMARY_JSON, "w") as f:
        json.dump(summary, f, indent=4)

    return summary


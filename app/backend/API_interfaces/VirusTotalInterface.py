import requests
import time
import json
from dotenv import load_dotenv
import os
from app import config




def scan_file(file_name: str):
    
    output = {"malware_types":[],"score":-1,"raw":{}}
    try:
        load_dotenv()
        ApiKey = os.getenv("VT_API_KEY")
        file_path = file_name

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

        timeout = 40
        print("loading data from Virus total")
        while timeout > 0:
            res = requests.get(analysis_url, headers=headers)
            res.raise_for_status()
            data = res.json()
            status = data["data"]["attributes"]["status"]
            if status == "completed":
                data = _analyse_data(data["data"])
                return data
            time.sleep(1)
            timeout -= 1

        return output
    except Exception as e:
        print(f"[scan_file VT] Error: {e}")
        return output


def _analyse_data(result):
    data = {}
    malware_types = []
    data = {"stats":result["attributes"]["status"],}
    for engine,details in result["attributes"]["results"].items():
        if(details["category"] != "undetected" and details["category"] != "type-unsupported" and  details["method"] != "timeout") and details["result"] != None:
            malware_types.append(details["result"])
    stats = result["attributes"]["stats"]

    return  {"malware_types":malware_types,"score":_calculate_malicious_score(stats),"raw":result}

def _calculate_malicious_score(stats: dict) -> int:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    total = malicious + suspicious + stats.get("undetected", 0) + stats.get("harmless", 0)
    if total == 0:
        return 0

    score = (2 * malicious + 1 * suspicious) / (2 * total) * 100
    return round(score)



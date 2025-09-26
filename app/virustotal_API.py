import requests
import time

def scan_file(api_key: str, file_path: str):
    headers = {"x-apikey": api_key}

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

    while True:
        res = requests.get(analysis_url, headers=headers)
        res.raise_for_status()
        data = res.json()
        status = data["data"]["attributes"]["status"]

        if status == "completed":
            return data
        else:
            print("Analysis in progress... waiting 5s")
            time.sleep(5)


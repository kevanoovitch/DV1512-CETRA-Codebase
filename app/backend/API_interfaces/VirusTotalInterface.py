import requests
import time
import json
from dotenv import load_dotenv
import os

##start of code

load_dotenv()

ApiKey = os.getenv("VT_API_KEY")

if not ApiKey:
    raise ValueError

base_url = "https://www.virustotal.com/api/v3/files/upload_url"

HEADERS = { "x-apikey": ApiKey}

file_path = "../uploaded/"


def scan_file(file_name: str):
    headers = {"x-apikey": ApiKey}

    with open(file_path, "rb") as f:
        files = {"file": (file_path+file_name, f)}
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
            return analyse_data(data["data"])

def analyse_data(result):
    data = {}
    detectedby = []
    data = {"stats":result["attributes"]["status"],}
    for engine,details in result["attributes"]["results"].items():
        if(details["category"] != "undetected" and details["category"] != "type-unsupported"):
            detectedby.add(details)
    stats = result["attributes"]["stats"]
    
    return  {"stats":stats, "detectedby":detectedby}
import requests
import json

"""url = "https://api.metadefender.com/v4/file"
headers = {
 "Content-Type": "application/octet-stream",
 "apikey": "d63269307d19d62ed65499ca90b16846",
 "filepath": "ext.zip"
}
payload = "\"<Payload in raw bytes>\""

response = requests.request("POST", url, headers=headers, data=payload)

print(response.text)

"""
#######################################################################################
"""
url = "https://api.metadefender.com/v4/file/bzI1MTAwMjlXREFkWUlyQmQ4WlphTnF4dC1q_mdaas"
headers = {
 "apikey": "d63269307d19d62ed65499ca90b16846"
}

response = requests.request("GET", url, headers=headers)

print(response.text)
"""
######################################################################################
""""
# Läs in JSON från fil
with open("scan_result.json", "r") as f:
    data = json.load(f)

scan_details = data["scan_results"]["scan_details"]

total_avs = len(scan_details)
detected_count = 0

# Kontrollera varje antivirus
for av, result in scan_details.items():
    # Här räknar vi som hot om scan_result_i > 0
    if result.get("scan_result_i", 0) > 0:
        detected_count += 1

# Beräkna score som procentandel "säkra" AV
score = (total_avs - detected_count) / total_avs * 100

# Skapa sammanfattnings-JSON
summary = {
    "total_avs": total_avs,
    "detected_avs": detected_count,
    "score_percentage": score,
    "verdict": "Safe" if detected_count == 0 else "Suspicious"
}

# Skriv ut till fil
with open("scan_summary.json", "w") as f:
    json.dump(summary, f, indent=4)

print("Sammanfattning sparad i scan_summary.json")


"""
######################################################################################

import time

API_KEY = "d63269307d19d62ed65499ca90b16846"
FILE_PATH = "ext.zip"  
SCAN_RESULT_JSON = "scan_result.json"
SUMMARY_JSON = "scan_summary.json"

url_upload = "https://api.metadefender.com/v4/file"
headers_upload = {
    "apikey": API_KEY,
    "Content-Type": "application/octet-stream"
}

with open(FILE_PATH, "rb") as f:
    payload = f.read()

response = requests.post(url_upload, headers=headers_upload, data=payload)
response_data = response.json()

file_id = response_data.get("data_id") or response_data.get("file_id")
if not file_id:
    raise Exception("Kunde inte hämta file_id från MetaDefender-responsen")

print(f"Filen skickad, file_id: {file_id}")

url_result = f"https://api.metadefender.com/v4/file/{file_id}"
headers_result = {"apikey": API_KEY}

while True:
    response = requests.get(url_result, headers=headers_result)
    data = response.json()

    progress = data.get("scan_results", {}).get("progress_percentage", 0)
    print(f"Scanning progress: {progress}%")
    
    if progress == 100:
        break
    time.sleep(3)

with open(SCAN_RESULT_JSON, "w") as f:
    json.dump(data, f, indent=4)
print(f"Rå scan-resultat sparat i {SCAN_RESULT_JSON}")

scan_details = data["scan_results"]["scan_details"]
total_avs = len(scan_details)
detected_count = 0

for av, result in scan_details.items():
    if result.get("scan_result_i", 0) > 0:
        detected_count += 1

score = detected_count / total_avs * 100
print(f"här är scoret: {round(score, 1)}")

summary = {
    "total_avs": total_avs,
    "detected_avs": detected_count,
    "score_percentage": score,
    "verdict": "Safe" if detected_count == 0 else "Suspicious"
}

with open(SUMMARY_JSON, "w") as f:
    json.dump(summary, f, indent=4)
print(f"Sammanfattning sparad i {SUMMARY_JSON}")




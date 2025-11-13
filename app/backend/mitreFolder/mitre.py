#fetch hash
# from app.backend.report_generator import file_hash  

#get curl command
import requests
import os
from dotenv import load_dotenv
load_dotenv()

filehash = "0efc314b1b7f6c74e772eb1f8f207ed50c2e702aed5e565081cbcf8f28f0fe26"
url = f"https://www.virustotal.com/api/v3/files/{hash}/behaviour_mitre_trees"

headers = {
    "accept": "application/json",
    "x-apikey": os.getenv("VT_API_KEY")
    
}

response = requests.get(url, headers=headers)

print(response.status_code)
print(response.json())

def mitre_report(filehash, response) -> dict:

    filehasher = [filehash]
    sandbox = response["sandbox_name"]
    tactics = response["tactic_id"]["tactic_name"]
    techniques = response["technique_id"]["technique_name"]

    parsed_response = {
        "filehash": filehasher,
        "sandbox": sandbox,
        "tactics": tactics,
        "techniques": techniques,
    }
    return parsed_response

#exists = requests.get(f"https://www.virustotal.com/api/v3/files/{hash}", headers=headers)



#print(exists.status_code)
#print(exists.json())
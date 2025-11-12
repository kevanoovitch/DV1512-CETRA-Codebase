#fetch hash
# from app.backend.report_generator import file_hash  

#get curl command
import requests
import os
from dotenv import load_dotenv
load_dotenv()

hash = "0efc314b1b7f6c74e772eb1f8f207ed50c2e702aed5e565081cbcf8f28f0fe26"
url = f"https://www.virustotal.com/api/v3/files/{hash}/behaviour_mitre_trees"

headers = {
    "accept": "application/json",
    "x-apikey": os.getenv("VT_API_KEY")
    
}
#exists = requests.get(f"https://www.virustotal.com/api/v3/files/{hash}", headers=headers)

response = requests.get(url, headers=headers)

print(response.status_code)
print(response.json())

#print(exists.status_code)
#print(exists.json())


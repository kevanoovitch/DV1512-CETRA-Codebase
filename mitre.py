#fetch hash
from app.backend.report_generator import file_hash  
hash = file_hash

#get curl command
import requests
headerAccept = {'accept: application/json'}
headerAPI = {'x-apikey: {VT_API_KEY}'}

response = requests.get("https://www.virustotal.com/api/v3/files/{hash}/behaviour_mitre_trees", headerAccept, headerAPI)
print(response.json())
"""
Give this function takes two arguments:
    - first one is String which contains teh request. (String)
    - second is the repons format. (Dict)
"""

request = [{
    "info":"please read the request and respond with the format of response",
    "request": "please anallyse teh data of this this isa reponse from secure annex of a chrome extention",
    "response": "repond in a free text fashion",
    "data":["Allows blocking or modifying network requests using declarative rules without intercepting them. in {\"permissions\": [\"storage\", \"tabs\", \"activeTab\", \"scripting\", \"webRequest\", \"alarms\", \"declarativeNetRequest\"]}", "High-risk permission: webRequest in 'permissions': ['storage', 'tabs', 'activeTab', 'scripting', 'webRequest', 'alarms', 'declarativeNetRequest']", "Allows creating, querying, modifying, and rearranging tabs in the browser. Can access URLs and favicons. in {\"permissions\": [\"storage\", \"tabs\", \"activeTab\", \"scripting\", \"webRequest\", \"alarms\", \"declarativeNetRequest\"]}", "Extension uses a service worker, which can run in the background even when the extension is not actively used. in {\"background\": {\"service_worker\": \"static/background/index.js\"}}", "Allows programmatic injection of scripts into web pages or access to content of specific tabs. in {\"permissions\": [\"storage\", \"tabs\", \"activeTab\", \"scripting\", \"webRequest\", \"alarms\", \"declarativeNetRequest\"]}", "Grants temporary access to the currently active tab when the user invokes the extension (e.g., clicks browser action). in {\"permissions\": [\"storage\", \"tabs\", \"activeTab\", \"scripting\", \"webRequest\", \"alarms\", \"declarativeNetRequest\"]}", "Content script can run on all websites, which is overly broad and potentially dangerous. in {\"content_scripts\": {\"matches\": [\"<all_urls>\"], \"js\": [\"yt.d9f6f88a.js\"], \"css\": [\"global.f48fde54.css\"]}}", "Extension has access to all URLs, which is extremely broad and potentially dangerous. in {\"host_permissions\": [\"<all_urls>\"]}", "Extension combines multiple high-impact permissions (including web request capabilities, broad host access, cookie manipulation, tab control, scripting, and storage), granting extensive control over user data and browser behavior. This combination significantly elevates potential security and privacy risks. in <no snippet provided>", "Allows observing network requests (viewing GET/POST, URLs) without modification capabilities if not paired with blocking. in {\"permissions\": [\"storage\", \"tabs\", \"activeTab\", \"scripting\", \"webRequest\", \"alarms\", \"declarativeNetRequest\"]}", "Scripting + <all_urls> significantly increases risk. in manifest", "webRequest + broad URL scope enables wide observation. in manifest", "Signature matched: Themes for Chrome and YouTube\u2122 Picture in Picture", "CSP Risk; XSS risk; Data exfil risk"]
}]


import os
from google import genai

def Ai_Helper() -> str:

    client = genai.Client()
    
    # Combine both into a single message
    response = client.models.generate_content(
        model="gemini-2.5-flash", # Use a valid model name
        contents="Explain how AI works in a few words",
    )

    print(response.output_text)
    return response.output_text


Ai_Helper()

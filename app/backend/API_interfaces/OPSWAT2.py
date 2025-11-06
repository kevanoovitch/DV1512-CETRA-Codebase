import requests
import json
import time
import os
from dotenv import load_dotenv
from app import constants





def scan_file(file_path):    
    """Skannar en fil med OPSWAT MetaDefender och returnerar score + malware_type som dictionary."""

    try:
        summary = {"score": -1, "malware_type": []}
        load_dotenv()
        API_KEY = os.getenv("OPSWAT_API_KEY")

        if not os.path.exists(file_path):
            print(f"[Fel] Filen '{file_path}' hittades inte.")
            return summary

        url_upload = "https://api.metadefender.com/v4/file"
        headers_upload = {
            "apikey": API_KEY,
            "Content-Type": "application/octet-stream"
        }

        with open(file_path, "rb") as f:
            payload = f.read()

        # Försök ladda upp filen
        try:
            response = requests.post(url_upload, headers=headers_upload, data=payload, timeout=15)
            response.raise_for_status()
        except requests.RequestException as e:
            print(f"[Fel] Kunde inte ladda upp filen: {e}")
            return summary

        response_data = response.json()
        file_id = response_data.get("data_id") or response_data.get("file_id")
        if not file_id:
            print("[Fel] Kunde inte hämta file_id från MetaDefender-svaret.")
            return summary

        # Hämta resultatet
        url_result = f"https://api.metadefender.com/v4/file/{file_id}"
        headers_result = {"apikey": API_KEY}

        while True:
            try:
                response = requests.get(url_result, headers=headers_result, timeout=10)
                response.raise_for_status()
                data = response.json()
            except requests.RequestException as e:
                print(f"[Fel] Kunde inte hämta skanningsresultat: {e}")
                return summary

            progress = data.get("scan_results", {}).get("progress_percentage", 0)
            if progress == 100:
                break
            time.sleep(3)

        # Spara hela resultatet
        try:
            with open(constants.SCAN_RESULT_JSON, "w") as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            print(f"[Varning] Kunde inte spara skanningsresultat: {e}")

        scan_details = data["scan_results"]["scan_details"]
        total_avs = len(scan_details)
        detected_count = sum(1 for av in scan_details.values() if av.get("scan_result_i", 0) > 0)
        score = int(round(detected_count / total_avs * 100, 0)) if total_avs else -1

        malware_type = data.get("malware_type", [])
        if isinstance(malware_type, str):
            malware_type = [malware_type]

        summary = {"score": score, "malware_type": malware_type}

        try:
            with open(constants.SUMMARY_JSON, "w") as f:
                json.dump(summary, f, indent=4)
        except Exception as e:
            print(f"[Varning] Kunde inte spara summary.json: {e}")

        return summary

    except Exception as e:
        print(f"[Allmänt fel] Något gick fel under skanningen: {e}")
        return summary

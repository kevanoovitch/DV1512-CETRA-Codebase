import requests
import json
import time
import os
import logging
from dotenv import load_dotenv
from app import constants
#########################
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("scanner.log", encoding="utf-8"),  #ta bort om du # om du vill spara i logfil
        logging.StreamHandler()
    ]
)

#########################
logger = logging.getLogger(__name__)

#print ("OPSWAT utanför scan_file")
def scan_file(file_path):    
    """Skannar en fil med OPSWAT MetaDefender och returnerar score + malware_type som dictionary."""
    logger.info (" function scan_file called")
    try:
        summary = {"score": -1, "malware_type": []}
        load_dotenv()
        API_KEY = os.getenv("OPSWAT_API_KEY")

        if not os.path.exists(file_path):
            logger.exception(f"[ErrorOPSWAT] File '{file_path}' could not be found.")
            return summary

        url_upload = "https://api.metadefender.com/v4/file"
        headers_upload = {
            "apikey": API_KEY,
            "Content-Type": "application/octet-stream"
        }

        with open(file_path, "rb") as f:
            payload = f.read()

        logger.info ("uploading file for scanning...")
        try:
            response = requests.post(url_upload, headers=headers_upload, data=payload, timeout=15)
            response.raise_for_status()
        except requests.RequestException as e:
            logger.exception(f"could not load the file: {e}")
            return summary

        response_data = response.json()
        file_id = response_data.get("data_id") or response_data.get("file_id")
        if not file_id:
            logger.exception("couldn't find file_id from MetaDefender-response.")
            return summary

        logger.info ("retrieving scan results...")
        url_result = f"https://api.metadefender.com/v4/file/{file_id}"
        headers_result = {"apikey": API_KEY}

        while True:
            try:
                response = requests.get(url_result, headers=headers_result, timeout=10)
                response.raise_for_status()
                data = response.json()
            except requests.RequestException as e:
                logger.exception(f"Could not retrieve scan results: {e}")
                return summary

            progress = data.get("scan_results", {}).get("progress_percentage", 0)
            if progress == 100:
                break
            time.sleep(3)

        logger.info ("save scan results...")
        try:
            with open(constants.SCAN_RESULT_JSON, "w") as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            logger.warning(f"could not save scan result: {e}")

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
            logger.warning(f"could not save summary.json: {e}")

        return summary

    except Exception as e:
        logger.exception(f"Something went wrong during the scanning: {e}")
        return summary
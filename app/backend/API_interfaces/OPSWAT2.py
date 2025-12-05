import requests
import time
import os
import logging
from dotenv import load_dotenv

from app import constants
from app.backend.utils.tag_matcher import analyze_label
from app.backend.utils import tag_matcher

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

load_dotenv()
API_KEY = os.getenv("OPSWAT_API_KEY")


def scan_file(file_path):
    
    logger.info("OPSWAT: function scan_file called")

    summary = {
        "malware_types": [],
        "analyzed_threats": []
        }

    if not API_KEY:
        logger.error("OPSWAT_API_KEY saknas i .env/environment")
        return summary

    if not os.path.exists(file_path):
        logger.error(f"[ErrorOPSWAT] File '{file_path}' could not be found.")
        return summary

    try:
        # 1. Ladda upp fil
        logger.info("OPSWAT: uploading file for scanning...")
        with open(file_path, "rb") as f:
            payload = f.read()

        response = requests.post(
            "https://api.metadefender.com/v4/file",
            headers={"apikey": API_KEY, "Content-Type": "application/octet-stream"},
            data=payload,
            timeout=15
        )
        response.raise_for_status()

        response_data = response.json()
        file_id = response_data.get("data_id") or response_data.get("file_id")
        if not file_id:
            logger.error("OPSWAT: couldn't find file_id from MetaDefender response.")
            return summary

        # 2. Poll resultat
        logger.info("OPSWAT: retrieving scan results...")
        url_result = f"https://api.metadefender.com/v4/file/{file_id}"
        headers_result = {"apikey": API_KEY}

        while True:
            response = requests.get(url_result, headers=headers_result, timeout=10)
            response.raise_for_status()
            data = response.json()

            progress = data.get("scan_results", {}).get("progress_percentage", 0)
            logger.info(f"OPSWAT: scan progress {progress}%")
            if progress == 100:
                break
            time.sleep(3)

        # 3. Extrahera threat_found
        scan_details = data["scan_results"]["scan_details"]
        raw_threats = [
            result.get("threat_found")
            for result in scan_details.values()
            if result.get("threat_found")
        ]
        raw_threats = list(set(raw_threats))
        summary["raw_threats"] = raw_threats
        
        # analyse threats
        analyzed_threats = []
        for label in raw_threats:
            #print(label)
            finding = analyze_label(label, constants.FINDINGS_API_NAMES["OP"] )
            analyzed_threats.append(finding)

            #print("Någon sträng: ", finding)

        logger.info(f"OPSWAT: summary: {analyzed_threats}")
        return analyzed_threats

    except Exception as e:
        logger.exception(f"OPSWAT: Something went wrong during the scanning: {e}")
        return summary


#if __name__ == "__main__":
    #result = scan_file("app/tests/test_crx/mil.crx")
    #print("Scan result:", result)

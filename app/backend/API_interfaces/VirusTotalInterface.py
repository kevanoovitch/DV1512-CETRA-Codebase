import os
import time
import logging
from dotenv import load_dotenv
import requests
import logging

logger = logging.getLogger(__name__)

load_dotenv()  # load once at import time

VT_API_URL = "https://www.virustotal.com/api/v3"
VT_API_KEY = os.getenv("VT_API_KEY")

def scan_file(file_path: str) -> dict:

    logger.info("FILEPATH: %s",file_path)
    output = {"malware_types": [], "score": -1, "raw": {}}

    try:
        if not VT_API_KEY:
            logger.error("VT_API_KEY is missing (not set in environment).")
            return output

        if not os.path.isfile(file_path):
            logger.error("File not found: %s", file_path)
            return output

        file_size = os.path.getsize(file_path)
        logger.info("Sending file: %s (%d bytes) to virustotal api", file_path, file_size)

        headers = {"x-apikey": VT_API_KEY}

        # Upload file
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            response = requests.post(f"{VT_API_URL}/files", headers=headers, files=files, timeout=60)

        logger.info("File sent, status_code=%s", response.status_code)
        response.raise_for_status()

        analysis_id = response.json()["data"]["id"]
        analysis_url = f"{VT_API_URL}/analyses/{analysis_id}"
        logger.info("Analysis ID: %s", analysis_id)

        # Poll for the result
        timeout_seconds = 40
        sleep_seconds = 1
        logger.info("Polling analysis (timeout=%ss)...", timeout_seconds)

        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            res = requests.get(analysis_url, headers=headers, timeout=30)
            res.raise_for_status()
            data = res.json()
            status = data["data"]["attributes"]["status"]

            logger.debug("Analysis status=%s", status)

            if status == "completed":
                logger.info("Analysis completed.")
                analysed = _analyse_data(data["data"])
                return analysed

            time.sleep(sleep_seconds)

        logger.warning("Analysis timed out after %s seconds.", timeout_seconds)
        return output

    except requests.RequestException as e:
        # Include stack trace and the exception message
        logger.exception("HTTP error during upload/poll: %s", e)
        return output
    except Exception as e:
        logger.exception("Unexpected error: %s", e)
        return output


def _analyse_data(result: dict) -> dict:
    try:
        attrs = result.get("attributes", {})
        stats = attrs.get("stats", {})
        results = attrs.get("results", {})

        malware_types = []
        for engine, details in results.items():
            # Safely access keys
            category = details.get("category")
            method = details.get("method")
            verdict = details.get("result")

            # Keep only meaningful detections
            if (
                verdict
                and category not in {"undetected", "type-unsupported"}
                and method != "timeout"
            ):
                malware_types.append(verdict)

        score = _calculate_malicious_score(stats)
        logger.info("Final score=%d, malware types=%s", score, malware_types)

        return {"malware_types": malware_types, "score": score, "raw": result}

    except Exception as e:
        logger.exception("Failed to analyze data: %s", e)
        return {"malware_types": [], "score": -1, "raw": result}


def _calculate_malicious_score(stats: dict) -> int:

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    harmless = stats.get("harmless", 0)

    total = malicious + suspicious + undetected + harmless
    if total == 0:
        logger.info("Total engines=0, returning score=0.")
        return 0

    score = (2 * malicious + 1 * suspicious) / (2 * total) * 100
    logger.info("Computed score=%.2f (malicious=%d, suspicious=%d, total=%d)",score, malicious, suspicious, total)
    return round(score)

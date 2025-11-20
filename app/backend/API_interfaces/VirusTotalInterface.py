import os
import time
import logging
from dotenv import load_dotenv
import requests
import logging
import hashlib

logger = logging.getLogger(__name__)

load_dotenv()  # load once at import time

VT_API_URL = "https://www.virustotal.com/api/v3"
VT_API_KEY = os.getenv("VT_API_KEY")

MAX_STANDARD_SIZE_BYTES = 32 * 1024 * 1024

def _get_upload_url() -> str:
    """Requests a special URL for uploading files larger than the standard limit."""
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(f"{VT_API_URL}/files/upload_url", headers=headers, timeout=30)
    response.raise_for_status()
    return response.json()["data"]

def _upload_file_standard(file_path: str, headers: dict) -> str:
    """Uploads file using the standard /files endpoint."""
    logger.info("Using STANDARD upload method.")
    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f)}
        response = requests.post(f"{VT_API_URL}/files", headers=headers, files=files, timeout=60)
    response.raise_for_status()
    return response.json()["data"]["id"]

def _upload_file_large(file_path: str, headers: dict) -> str:
    """Uploads file using the large file upload URL."""
    logger.info("Using LARGE file upload method.")
    upload_url = _get_upload_url() # This function will raise an exception on error

    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f)}
        response = requests.post(upload_url, headers=headers, files=files, timeout=300) # Increased timeout for large file
    
    response.raise_for_status()
    return response.json()["data"]["id"]

def _analyse_data(result: dict, output:dict) -> dict:
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
        output["malware_types"] = malware_types
        output["score"] = score
        output["raw"] = result
        return output

    except Exception as e:
        logger.exception("Failed to analyze data: %s", e)
        return output

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

def get_vt_behaviours(file_hash: str):
    logger.info("Attempting to retrieve DETAILED dynamic analysis (behaviours) for hash: %s", file_hash)
    url = f"{VT_API_URL}/files/{file_hash}/behaviours"
    headers = {
        "x-apikey": VT_API_KEY,
        "Accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()  # raises if non-2xx

        return response.json()
    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 404:
            logger.warning("No detailed dynamic analysis report found for file hash %s.", file_hash)
        elif response.status_code == 401:
            logger.error("Unauthorized: Check if your API key supports behaviour reports (Private API required).")
        else:
            logger.error("HTTP error retrieving detailed behaviours (%s): %s", response.status_code, http_err)
    except Exception as e:
        logger.exception("Failed to retrieve or print VT detailed behaviours: %s", e)

def get_vt_behaviour_summary(file_hash: str):
    logger.info("Attempting to retrieve SUMMARY dynamic analysis (behaviour_summary) for hash: %s", file_hash)
    url = f"{VT_API_URL}/files/{file_hash}/behaviour_summary"
    headers = {
        "x-apikey": VT_API_KEY,
        "Accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()  # raises if non-2xx
        
        return response.json()

    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 404:
            logger.warning("No behaviour summary found for file hash %s.", file_hash)
        elif response.status_code == 401:
            logger.error("Unauthorized: Check if your API key supports summary reports (Private API required).")
        else:
            logger.error("HTTP error retrieving behaviour summary (%s): %s", response.status_code, http_err)
    except Exception as e:
        logger.exception("Failed to retrieve or print VT behaviour summary: %s", e)

def scan_file(file_path: str, file_hash:str) -> dict:

    logger.info("FILEPATH: %s",file_path)
    output = {"malware_types": [], "score": -1, "raw": {}, "behavior": {}}

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
        analysis_id = None

        
        logger.info("Getting file behavior report from virustotal")
        

        behavior = get_vt_behaviour_summary(file_hash)
        output["behaviour"] = behavior

        if file_size > MAX_STANDARD_SIZE_BYTES:
            analysis_id = _upload_file_large(file_path, headers)
        else:
            analysis_id = _upload_file_standard(file_path, headers)

        logger.info("File sent, status_code=200-202 (implied by no error)")
        logger.info("Analysis ID: %s", analysis_id)

        # Poll for the result
        analysis_url = f"{VT_API_URL}/analyses/{analysis_id}"
        timeout_seconds = 500
        sleep_seconds = 5
        logger.info("Polling analysis (timeout=%ss)...", timeout_seconds)
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            res = requests.get(analysis_url, headers=headers, timeout=30)
            res.raise_for_status()
            data = res.json()
            status = data["data"]["attributes"]["status"]
            logger.info("Analysis status=%s", status)
            if status == "completed":
                logger.info("Analysis completed.")
                analysed = _analyse_data(data["data"],output)
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
import os
import time
import logging
from dotenv import load_dotenv
from google import genai

load_dotenv()

logger = logging.getLogger(__name__)

# Configure logging once in your app entrypoint, example:
# logging.basicConfig(level=logging.INFO)

def Ai_Helper(request: str, response: str, data: list) -> str | None:
    client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

    logger.debug("Ai_Helper called with data=%s", data)

    payload = {
        "info": "please read the request and respond with the format of response",
        "request": request,
        "response": response,
        "data": data,
    }

    max_retries = 4
    wait_seconds = 5

    logger.info("Asking Gemini to: %s", request)

    for attempt in range(1, max_retries + 1):
        try:
            gemini_response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=str(payload)
            )
            # Success
            logger.info(
                "Gemini call succeeded on attempt %d/%d",
                attempt,
                max_retries
            )
            return gemini_response.text

        except Exception as e:
            error_str = str(e)

            # Check specifically for 503
            is_503 = "503" in error_str

            if is_503 and attempt < max_retries:
                logger.warning(
                    "Gemini returned 503 (Service Unavailable), "
                    "retrying in %d seconds... (attempt %d/%d)",
                    wait_seconds,
                    attempt,
                    max_retries
                )
                time.sleep(wait_seconds)
                continue

            # Final failure (non-503, or 503 after last attempt)
            logger.error(
                "Gemini API call failed on attempt %d/%d: %s",
                attempt,
                max_retries,
                error_str
            )
            return None

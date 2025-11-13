from app import config
from app import constants

import logging
import json
import os
from pathlib import Path
from typing import Any, Callable, Dict

import requests
from dotenv import load_dotenv
from app.backend.utils.ExtensionIDConverter import ExtensionIDConverter

logger = logging.getLogger(__name__)

class Interface_Secure_Annex:
    SECTION_MAP = {
        "manifest": "/manifest",
        "vulnerabilities": "/vulnerabilities",
        "signatures": "/signatures",
        "urls": "/urls",
        "analysis": "/analysis",
    }

    SECTION_TITLES = {
        "manifest": "Manifest",
        "vulnerabilities": "Vulnerabilities",
        "signatures": "Signatures",
        "urls": "URLs",
        "analysis": "AI-Analysis",
    }

    def __init__(self):
        load_dotenv()
        self.ApiKey = os.getenv("SA_API_KEY")
        self.ApiEndpoint = os.getenv("SA_API_ENDPOINT")
        self.HEADERS = {"x-api-key": self.ApiKey}
        self.dev_mode = getattr(config, "DEV_MODE", False)
        default_cache = getattr(constants, "SA_OUTPUT_FILE", "backend/output.json")
        self.cache_path = Path(default_cache)
        self.fixture_path = self.cache_path
        self.conveter = ExtensionIDConverter()

   

    # <--- Exposed functions --->

    def perform_scan(self, extension: str, path: Path) -> None:
        """
        Fetch Secure Annex sections (or load cached in dev mode) and write to `path`.
        Does not parse.
        """
        logger.info("SA scan start", extra={"extension_id": extension, "out_path": str(path), "dev_mode": self.dev_mode})
        path.parent.mkdir(parents=True, exist_ok=True)



        #verify that input is an extensionID
        if (self._is_extension_id(extension) != True):
            logger.info("Input was not an ID — calling converter", extra={"extension": extension})
            extension = self.conveter.convert_file_to_id(extension)

            if extension is None :
                logger.warning("Missing ID — could not convert file to extension ID")
                return None

        if self.dev_mode:
            logger.info("DEV MODE — loading cached report", extra={"cache_path": str(path)})
            raw_report = self._load_cached_report(path)
        else:
            # build fetcher map
            fetchers: Dict[str, Callable[[str], Any]] = {
                key: getattr(self, f"fetch_{key}") for key in self.SECTION_MAP
            }

            raw_report: Dict[str, Any] = {}
            for section, fetcher in fetchers.items():
                try:
                    raw_report[section] = fetcher(extension)
                except Exception as exc:
                    logger.info("DEV MODE — loading cached report", extra={"cache_path": str(path)})
                    raw_report[section] = {"error": str(exc)}

        # Always write the report out
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(raw_report, indent=2), encoding="utf-8")
        tmp.replace(path)

    # < --- private functions -- >

    def _is_extension_id(self, value) -> bool:
        # Chrome extension IDs are 32 lowercase letters (a–z).
        return (
            isinstance(value, str)
            and len(value) == 32
            and value.islower()
            and value.isalpha()
        )



    def _load_cached_report(self, path: Path) -> Dict[str, Any]:
        if not path.exists():
            raise FileNotFoundError(f"No cached SA report at {path}")
        return json.loads(path.read_text(encoding="utf-8"))

    # <--- Getters & fetchers --->

    def fetch_resource(self, extension: str, endpoint: str):
        """Generic helper function to query Secure Annex."""
        url = f"{self.ApiEndpoint}{endpoint}"

        try:
            response = requests.get(
                url,
                headers=self.HEADERS,
                params={"extension_id": extension},
            )
            response.raise_for_status()
            try:
                return response.json()
            except ValueError:
                return response.text
        except requests.RequestException as exc:  # pragma: no cover - network errors
            return {"error": str(exc)}

    def fetch_manifest(self, extension: str):
        return self.fetch_resource(extension, self.SECTION_MAP["manifest"])

    def fetch_vulnerabilities(self, extension: str):
        return self.fetch_resource(extension, self.SECTION_MAP["vulnerabilities"])

    def fetch_signatures(self, extension: str):
        return self.fetch_resource(extension, self.SECTION_MAP["signatures"])

    def fetch_urls(self, extension: str):
        return self.fetch_resource(extension, self.SECTION_MAP["urls"])

    def fetch_analysis(self, extension: str):
        return self.fetch_resource(extension, self.SECTION_MAP["analysis"])

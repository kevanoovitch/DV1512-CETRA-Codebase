import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, Optional

import requests
from dotenv import load_dotenv
from rich import print_json
from rich.console import Console

import config
import constants


class ISecureAnnex:
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

    def __init__(self, api_key, api_endpoint):
        load_dotenv()
        self.ApiKey = os.getenv("SA_API_KEY")
        self.ApiEndpoint = os.getenv("SA_API_ENDPOINT")
        self.HEADERS = {"x-api-key": self.ApiKey}
        self.dev_mode = getattr(config, "DEV_MODE", False)
        default_cache = getattr(constants, "SA_OUTPUT_FILE", "backend/output.json")
        self.cache_path = Path(default_cache)
        self.fixture_path = self.cache_path

    # <--- Exposed functions --->

    def perform_scan(self, extension: str, path: Path) -> None:
        """
        Fetch Secure Annex sections (or load cached in dev mode) and write to `path`.
        Does not parse.
        """
        path.parent.mkdir(parents=True, exist_ok=True)

        if self.dev_mode:
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
                    raw_report[section] = {"error": str(exc)}

        # Always write the report out
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(raw_report, indent=2), encoding="utf-8")
        tmp.replace(path)


    def print_analysis(
            self,
            report: Optional[Dict[str, Any]] = None,
            *,
            path: Optional[Path | str] = None,) -> None:
            data = report if report is not None else self._load_cached_report(Path(constants.SA_OUTPUT_FILE))
            console = Console()

            for section_key, title in self.SECTION_TITLES.items():
                console.rule(f"[bold cyan]{title}[/bold cyan]")
                payload = data.get(section_key, {"warning": "section missing"})
                self.pretty_print_json(payload)

            if self.dev_mode == True:
                console.rule(f"[bold red]DEV MODE IS ON[/bold red]")

    # < --- private functions -- > 

    def _load_cached_report(self, path: Path) -> Dict[str, Any]:
        if not path.exists():
            raise FileNotFoundError(f"No cached SA report at {path}")
        return json.loads(path.read_text(encoding="utf-8"))


    @staticmethod
    def pretty_print_json(data: Any) -> None:
        if isinstance(data, str):
            try:
                print_json(data)
                return
            except Exception:  # pragma: no cover - fall back to raw print
                print(data)
                return
        print_json(json.dumps(data))

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

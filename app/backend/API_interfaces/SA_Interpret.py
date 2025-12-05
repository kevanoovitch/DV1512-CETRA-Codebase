from app import constants
from app.backend.utils.tag_matcher import analyze_label, Finding

import logging
from typing import Any, Dict, List, Optional
from pathlib import Path
import json

logger = logging.getLogger(__name__)


class SecureAnnex_interpretator:

    def __init__(self):
        self.report_path = constants.SA_OUTPUT_FILE
        self.findings: List[Finding] = []
        self.failed = False
        self.failure_reason: Optional[str] = None


    def interpret_output(self) -> List[Dict[str, Any]]:
        """
        Load SA output JSON file from constants.SA_OUTPUT_FILE and parse into a list of findings.
        """

        self.findings = []
        self.failed = False
        self.failure_reason = None

        logger.info("SA interpret_output: starting parse of %s", constants.SA_OUTPUT_FILE)
        path = Path(constants.SA_OUTPUT_FILE)

        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            logger.exception("SA output file not found: %s", path)
            self.failed = True
            self.failure_reason = "sa_output_missing"
            return [self._failure_finding()]
        except json.JSONDecodeError:
            logger.exception("Malformed SA JSON in %s: %s", path)
            self.failed = True
            self.failure_reason = "sa_output_malformed"
            return [self._failure_finding()]



        for section, data in payload.items():
            if isinstance(data, dict):
                err = str(data.get("error", ""))
                if "401" in err:
                    logger.warning("SA unauthorized (401) in section '%s': %s", section, data.get("error"))
                    self.failed = True
                    self.failure_reason = "sa_unauthorized"
                    return [self._failure_finding()]

        manifest_items = (payload.get("manifest") or {}).get("result") or []
        signature_items  = (payload.get("signatures") or {}).get("result") or []
        url_items = (payload.get("urls") or {}).get("result") or []
        analysis_items   = (payload.get("analysis") or {}).get("result") or []

        if not (manifest_items or signature_items or url_items or analysis_items):
            logger.warning("SA payload contained no actionable results (all sections empty).")
            return []

        self._interpret_manifest(manifest_items)
        self._interpret_signatures(signature_items)
        self._interpret_urls(url_items)
        self._interpret_analysis(analysis_items)

        logger.info("SA interpret_output: produced %d findings (manifest=%d, signatures=%d, urls=%d, analysis=%d)",
                    len(self.findings), len(manifest_items), len(signature_items), len(url_items), len(analysis_items))
        return self.findings

    def _make_finding(
            self,
            source: str,
            label: str,
            detail: str,
            severity: Optional[int] = None,
            family: Optional[str] = None,
            api: str = constants.FINDINGS_API_NAMES["SA"],
        ) -> Finding:

        risk = analyze_label(label, api=constants.FINDINGS_API_NAMES["SA"])

        context_parts = []
        if source:
            context_parts.append(f"source={source}")
        if severity is not None:
            context_parts.append(f"sev={severity}")
        if detail:

            short_detail = detail.replace("\n", " ")
            if len(short_detail) > 160:
                short_detail = short_detail[:157] + "...."
            context_parts.append(f"detail={short_detail}")

        context = " | ".join(context_parts) if context_parts else "no context"
        logger.debug(
            "SA finding generated: label=%s tag=%s type=%s category=%s score=%s (%s)",
            label,
            risk.tag,
            risk.type,
            risk.category,
            risk.score,
            context,
        )

        return Finding(
            tag=risk.tag,
            type=risk.type,
            category=risk.category,
            score=risk.score,
            family=None,
            api=constants.FINDINGS_API_NAMES["SA"]
        )

    def _add_finding(self, finding: Finding) -> None:
        """Append finding only when it has a meaningful score."""
        if finding.score == -1:
            logger.debug(
                "SA finding skipped (score -1): tag=%s type=%s category=%s",
                finding.tag,
                finding.type,
                finding.category,
            )
            return
        self.findings.append(finding)
    #TODO: this is wrong it should return a default finding no?
    def _failure_finding(self) -> dict:
        """Sentinel finding to mark SA failure; allows downstream code to distinguish errors."""
        return Finding(
            tag=None,
            type=None,
            category=None,
            score=-1,
            family=None,
            api=constants.FINDINGS_API_NAMES["SA"]
        )

    def _interpret_manifest(self, items: List[Dict[str, Any]]) -> None:
        """
        Create findings from manifest results and add synergy findings where applicable.
        """
        def _short(snippet: str, limit: int = 180) -> str:
            s = (snippet or "").replace("\n", " ").strip()
            return s if len(s) <= limit else s[:limit] + "..."

        has_all_urls = False
        has_cs_all_urls = False
        has_scripting = False
        has_webrequest = False

        for it in items:

            description = (it.get("description") or "").strip()
            snip = _short(it.get("snippet") or "")

            label = (it.get("risk_type") or "").strip()
            detail = f"{description} in {snip or '<no snippet provided>'}" if description else (snip or "<no snippet provided>")
            sev = it.get("severity")
            self._add_finding(self._make_finding("manifest", label, detail, severity=sev))
            logger.debug("SA manifest finding added: label=%s detail=%s", label, detail)

            rtype_upper = label.upper()
            if rtype_upper == "ALL_URLS_ACCESS":
                has_all_urls = True
            if rtype_upper == "CONTENT_SCRIPT_ALL_URLS":
                has_cs_all_urls = True
            if rtype_upper == "SCRIPTING_PERMISSION":
                has_scripting = True
            if rtype_upper == "WEBREQUEST":
                has_webrequest = True

        if has_all_urls and has_scripting:
            self._add_finding(self._make_finding("manifest", "all_urls_access", "Scripting + <all_urls> significantly increases risk.", severity=None))
            logger.info("SA manifest synergy finding added: scripting + all_urls_access")

        if has_webrequest and (has_all_urls or has_cs_all_urls):
            self._add_finding(self._make_finding("manifest", "webrequest_surveillance", "webRequest + broad URL scope enables wide observation.", severity=None))
            logger.info("SA manifest synergy finding added: webrequest + broad URL")

    def _interpret_urls(self, urls: List[Dict[str, Any]]):
        for u in urls:
            url = (u.get("url") or "").strip()
            file_path = (u.get("file_path") or "").strip()
            domain = (u.get("domain") or "").strip()

            bad = False
            url_label = None
            severity: Optional[int] = None

            if url.startswith("http://"):
                bad = True
                url_label = "http_usage"
                severity = 4

            if ("background" in file_path.lower() or "static/background" in file_path.lower()) and domain and not domain.endswith(("google.com", "chrome.google.com")):
                bad = True
                url_label = url_label or "suspicious_network_request"
                severity = 6
                if not url:
                    url = domain

            if bad and (url or domain):
                detail = f"malicious url: {url or domain} from this file {file_path}"
                label_for_tag = url_label or (url or domain)
                self._add_finding(self._make_finding("urls", label_for_tag, detail, severity=severity))
                logger.info("SA url finding added: label=%s detail=%s sev=%s", label_for_tag, detail, severity)

    def _interpret_analysis(self, rows: List[Dict[str, Any]]) -> None:
        for r in rows:

            text = (r.get("analysis") or "")
            text_l = text.lower()

            if "content security policy" in text_l or "csp" in text_l:
                self._add_finding(self._make_finding("analysis", "csp_disabled", "CSP Risk", severity=8))
                logger.info("SA analysis finding added: csp_disabled")

            if "remote config" in text_l:
                self._add_finding(self._make_finding("analysis", "remote_script_dependency", "Remote configuration", severity=6))
                logger.info("SA analysis finding added: remote_script_dependency")

            if "xss" in text_l:
                self._add_finding(self._make_finding("analysis", "xss", "XSS risk", severity=6))
                logger.info("SA analysis finding added: xss")

            if "data theft" in text_l or "exfil" in text_l:
                self._add_finding(self._make_finding("analysis", "data_exfiltration", "Data exfil risk", severity=6))
                logger.info("SA analysis finding added: data_exfiltration")

    def _interpret_signatures(self, sigs: List[Dict[str, Any]]) -> None:

        for s in sigs:
            sev_map = {"critical": 9, "high": 8, "medium": 6, "low": 3}
            meta = s.get("meta") or {}
            sev_text = (meta.get("severity") or "").lower()
            sev_num = sev_map.get(sev_text, 4)
            label = s.get("name") or s.get("rule") or sev_text
            detail = f"Signature matched: {label}"
            self._add_finding(self._make_finding("signatures", label, detail, severity=sev_num))
            logger.info("SA signature finding added: label=%s sev=%s", label, sev_num)

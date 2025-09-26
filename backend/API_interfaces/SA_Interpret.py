import constants
import config
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from pathlib import Path
import json





class SecureAnnex_interpretator:

    def __init__(self):
        self.dev_mode = config.DEV_MODE
        self.report_path = constants.SA_OUTPUT_FILE
        self.combined_score = 0


    SECTION_CAPS = {
    "manifest": 60,
    "signatures": 20,
    "urls": 15,
    "analysis": 20,
    }

    # --- Exposed functions --- #

    def interpret_output(self) -> dict:
        """
        Load SA output JSON file from constants.SA_OUTPUT_FILE and parse.
        """

        path = Path(constants.SA_OUTPUT_FILE)
        payload = json.loads(path.read_text(encoding="utf-8"))

        manifest_items = (payload.get("manifest") or {}).get("result") or []
        signature_items  = (payload.get("signatures") or {}).get("result") or []
        url_items = (payload.get("urls") or {}).get("result") or []
        analysis_items   = (payload.get("analysis") or {}).get("result") or []

        findings = []
        findings += self._interpret_manifest(manifest_items)
        findings += self._interpret_signatures(signature_items)
        findings += self._interpret_urls(url_items)
        findings += self._interpret_analysis(analysis_items)

        #Compute final score with per-section
        score = self._final_score(findings)

        return {
            "score": score,
            "findings" : findings,
        }
    
    # --- private functions and modules ---

    @dataclass
    class Finding:
        source : str
        risk_type: str
        severity: Optional[int]
        description: str
        extra: Dict[str, Any] = field(default_factory=dict)
        points: int = 0
    

    def _severity_points(self,sev: Optional[int], factor:int = 5) -> int:
        """Convert SA severity score to a points within the defined caps"""

        if sev is None:
            return 0
        try:
            s = int(sev)
        except (TypeError, ValueError):
            return 0
        s = max(0, min(10,s))
        return s * factor
        
    def _cap_section(self, findings: List[Finding], section: str) -> int:
        cap = self.SECTION_CAPS[section]
        subtotal = sum(f.points for f in findings if f.source == section)
        if subtotal <= cap:
            return subtotal
        
        return cap

    def _final_score(self, all_findings: List[Finding]) -> int:
        total = 0
        total += self._cap_section(all_findings, "manifest")
        total += self._cap_section(all_findings, "signatures")
        total += self._cap_section(all_findings, "urls")
        total += self._cap_section(all_findings, "analysis")
        return max(0, min(100,total))




    #TODO: Take SA's description field and add to a log file
    def _interpret_manifest(self, items: List[Dict[str, Any]]) -> List[Finding]:
        """
        return a score
        """
        findings: List[SecureAnnex_interpretator.Finding] = []        
        has_all_urls = False
        has_cs_all_urls = False
        has_scripting = False
        has_webrequest = False

        

        for it in items:
            
            rtype = it.get("risk_type","")
            desc  = it.get("description","")
            sev   = it.get("severity")
            pts = self._severity_points(sev,factor = 5)
            
            if rtype == "ALL_URLS_ACCESS": has_all_urls = True
            if rtype == "CONTENT_SCRIPT_ALL_URLS": has_cs_all_urls = True
            if rtype == "SCRIPTING_PERMISSION": has_scripting = True
            if rtype == "WEBREQUEST": has_webrequest = True

            findings.append(self.Finding("manifest", rtype, sev, desc, points = pts))

            #Synergy bumps
            if has_all_urls and has_scripting:
                findings.append(self.Finding("manifest", "SYNERGY_ALLURLS_SCRIPTING", None, "Scripting + <all_urls> significantly increases risk.", points=10 ))

            if has_webrequest and (has_all_urls or has_cs_all_urls):
                findings.append(self.Finding("manifest", "SYNERGY_WEBREQ_GLOBAL", None, "webRequest + broad URL scope enables wide observation.", points=10))            

        return findings
        
    def _interpret_signatures(self, sigs: List[Dict[str, Any]]) -> List[Finding]:
        findings: List[SecureAnnex_interpretator.Finding] = []

        for s in sigs:
            meta = s.get("meta") or {}
            sev_text = (meta.get("severity") or "").lower()

            sev_map = {"critical": 9, "high": 8, "medium": 6, "low": 3}
            sev = sev_map.get(sev_text, 4)
            desc = f"Signature matched: {s.get('name') or s.get('rule')}"
            pts = self._severity_points(sev, factor=2)
            findings.append(self.Finding(
                source="signatures", 
                risk_type=s.get("rule"),
                severity=sev,
                description=desc, 
                points=pts
            ))
        
        return findings
    
    def _interpret_urls(self, urls: List[Dict[str, Any]]) -> List[Finding]:
        findings: List[SecureAnnex_interpretator.Finding] = []

        for u in urls: 
            url = u.get("url") or ""
            file_path = u.get("file_path") or ""
            domain = u.get("domain") or ""

            if url.startswith("http://"):
                findings.append(self.Finding(
                    source="urls",
                    risk_type="PLAINTEXT_URL",
                    severity=4,
                    description=f"Plain HTTP endpoint referenced: {url}",
                    points=self._severity_points(4, factor=2)
                ))

            if ("background" in file_path or "static/background" in file_path) and domain and not domain.endswith(("google.com", "chrome.google.com")):
                findings.append(self.Finding(
                    source="urls",
                    risk_type="EXTERNAL_CONTROL_DOMAIN",
                    severity=6, 
                    description=f"Background references external domain: {domain}",
                    points = self._severity_points(6, factor=2)
                ))
        return findings

    def _interpret_analysis(self, rows: List[Dict[str,Any]]) -> List[Finding]:
        findings: List[SecureAnnex_interpretator.Finding] = []
        for r in rows: 
            text = (r.get("analysis") or "")
            text_l = text.lower()
            sev = 0
            notes = []

            if "content security policy" in text_l or "csp" in text_l:
                sev = max(sev, 8); notes.append("CSP Risk")
            if "remote config" in text_l:
                sev = max(sev, 6); notes.append("Remote configuration")
            if "xss" in text_l:
                sev = max(sev,6); notes.append("XSS risk")
            if "data theft" in text_l or "exfil" in text_l:
                sev = max(sev, 6); notes.append("Data exfil risk")

            if sev > 0:
                pts = self._severity_points(sev, factor=2)
                findings.append(self.Finding(
                    source="analysis",
                    risk_type="AI_ANALYSIS_FLAGS",
                    severity=sev,
                    description="; ".join(notes) or "AI analysis flagged issues",
                    points=pts
                ))
        return findings


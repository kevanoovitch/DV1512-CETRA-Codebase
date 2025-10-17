from app import config
from app import constants

from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from pathlib import Path
import json

class SecureAnnex_interpretator:

    def __init__(self):
        self.report_path = constants.SA_OUTPUT_FILE
        self.combined_score = 0
        self.returnDict = {
            "urls": [], 
            "descriptions": [],
            "risk_types" : [],
            "score":int,
        }

        self.section_points = {"manifest": 0, "signatures": 0, "urls": 0, "analysis": 0}




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

        self._interpret_manifest(manifest_items)
        self._interpret_signatures(signature_items)
        self._interpret_urls(url_items)
        self._interpret_analysis(analysis_items)

        self.returnDict["score"] = self._final_score()
        return self.returnDict

    
    # --- private functions and modules ---

    def _add_points(self, section: str, pts: int) -> None:
        if pts and section in self.section_points:
            self.section_points[section] += int(pts)

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
        
    def _cap_section(self, section: str) -> int:
        cap = self.SECTION_CAPS[section]
        subtotal = self.section_points.get(section, 0)
        return subtotal if subtotal <= cap else cap

    def _final_score(self) -> int:
        total = 0
        total += self._cap_section("manifest")
        total += self._cap_section("signatures")
        total += self._cap_section("urls")
        total += self._cap_section("analysis")
        return max(0, min(100, total))



   
    def _interpret_manifest(self, items: List[Dict[str, Any]]) -> None:
        """
        Add 'description in <snippet>' lines to returnDict['descriptions'],
        collect unique risk types into returnDict['risk_types'],
        and accumulate manifest points.
        """
        # use the plural key consistently
        descs = self.returnDict.setdefault("descriptions", [])
        seen_descs = set(descs)

        risk_types = self.returnDict.setdefault("risk_types", [])
        seen_risks = set(risk_types)

        def _short(snippet: str, limit: int = 180) -> str:
            s = (snippet or "").replace("\n", " ").strip()
            return s if len(s) <= limit else s[:limit] + "..."

        has_all_urls = False
        has_cs_all_urls = False
        has_scripting = False
        has_webrequest = False

        for it in items:
            rtype = (it.get("risk_type") or "").strip()
            description = (it.get("description") or "").strip()
            snip = _short(it.get("snippet") or "")
            sev = it.get("severity")

            # points (manifest factor=5)
            pts = self._severity_points(sev, factor=5)
            self._add_points("manifest", pts)

            if rtype == "ALL_URLS_ACCESS": has_all_urls = True
            if rtype == "CONTENT_SCRIPT_ALL_URLS": has_cs_all_urls = True
            if rtype == "SCRIPTING_PERMISSION": has_scripting = True
            if rtype == "WEBREQUEST": has_webrequest = True

            # collect unique risk types
            if rtype and rtype not in seen_risks:
                risk_types.append(rtype)
                seen_risks.add(rtype)

            # collect description lines
            if description:
                msg = f"{description} in {snip or '<no snippet provided>'}"
                if msg not in seen_descs:
                    descs.append(msg)
                    seen_descs.add(msg)

        # Synergy notes + points
        if has_all_urls and has_scripting:
            msg = "Scripting + <all_urls> significantly increases risk. in manifest"
            if msg not in seen_descs:
                descs.append(msg); seen_descs.add(msg)
            self._add_points("manifest", 10)

        if has_webrequest and (has_all_urls or has_cs_all_urls):
            msg = "webRequest + broad URL scope enables wide observation. in manifest"
            if msg not in seen_descs:
                descs.append(msg); seen_descs.add(msg)
            self._add_points("manifest", 10)


    
    def _interpret_urls(self, urls: List[Dict[str, Any]]):
       
       
        seen = set(self.returnDict.get("urls", [])) 


        for u in urls: 
            url = (u.get("url") or "").strip()
            file_path = (u.get("file_path") or "").strip()
            domain = (u.get("domain") or "").strip()
            

            bad = False
            url_pts = 0

            # Rule 1: Plain HTTP endpoint
            if url.startswith("http://"):
                bad = True
                url_pts = max(url_pts, self._severity_points(4, factor=2))

            # Rule 2: Background script referencing external (non-Google) domain
            if (
                ("background" in file_path.lower() or "static/background" in file_path.lower()) and domain 
                and not domain.endswith(("google.com", "chrome.google.com"))
                
            ):
                
                bad = True
                url_pts = max(url_pts, self._severity_points(6, factor=2))
            
                if not url:
                    url = domain

            if bad and url: 
                msg = f"malicious url: {url} from this file {file_path}"
                if msg not in seen:
                    self.returnDict["urls"].append(msg)
                    seen.add(msg)
                self._add_points("urls", url_pts)
                
    def _interpret_analysis(self, rows: List[Dict[str, Any]]) -> None:
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
                sev = max(sev, 6); notes.append("XSS risk")
            if "data theft" in text_l or "exfil" in text_l:
                sev = max(sev, 6); notes.append("Data exfil risk")

            if sev > 0:
                pts = self._severity_points(sev, factor=2)
                self._add_points("analysis", pts)
                line = "; ".join(notes) if notes else "AI analysis flagged issues"
                if line not in self.returnDict["descriptions"]:
                    self.returnDict["descriptions"].append(line)

    def _interpret_signatures(self, sigs: List[Dict[str, Any]]) -> None:
        
        sev_map = {"critical": 9, "high": 8, "medium": 6, "low": 3}

        for s in sigs:
            meta = s.get("meta") or {}
            sev_text = (meta.get("severity") or "").lower()
            sev = sev_map.get(sev_text, 4)
            pts = self._severity_points(sev, factor=2)
            self._add_points("signatures", pts)

            # optional: human-readable line
            desc = f"Signature matched: {s.get('name') or s.get('rule')}"
            if desc and desc not in self.returnDict["descriptions"]:
                self.returnDict["descriptions"].append(desc)

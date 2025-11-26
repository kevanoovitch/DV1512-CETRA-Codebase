"""
risk_mapping.py

Module for mapping VirusTotal/OPSWAT labels or internal strings
to normalized risk "types" and scores.

Public API:
    analyze_label(label: str) -> dict

Return format:
    {
        "tag": <specific matched term, e.g. "trojan", "miner", "all_urls_access">,
        "type": <canonical type, e.g. "code_execution", "cryptominer", "all_urls_access">,
        "category": <broad category: "malware" | "vulnerability" | "permission"
                     | "privacy" | "obfuscation" | "supply_chain" | "metadata" | "unknown">,
        "score": <0-100 int>
    }
"""

import re
from typing import Dict, List, Set, Any, Tuple

# ============================================================
# CANONICAL TYPES → SCORES (0–100)
# ============================================================

TAG_SCORES: Dict[str, int] = {
    # Malware & malicious behavior
    "adware": 25,
    "spyware": 75,
    "credential_stealer": 90,
    "cookie_hijacking": 75,
    "keylogger": 90,
    "clipboard_hijacker": 75,
    "session_hijacking": 75,
    "dom_injection": 75,
    "backdoor": 90,
    "c2_communication": 90,
    "payload_downloader": 90,
    "polymorphic_script": 75,
    "obfuscated_code": 50,
    "self_modifying_script": 90,
    "remote_code_loader": 90,
    "cryptominer": 80,
    "browser_hijacker": 75,
    "search_hijacker": 60,
    "redirect_injector": 60,
    "phishing_script": 90,
    "data_exfiltration": 90,
    "tracking_beacon": 40,
    "web_fingerprinting": 60,
    "permission_escalation": 85,
    "local_storage_theft": 85,
    "indexeddb_sniffing": 80,

    # Vulnerabilities
    "xss": 70,
    "reflected_xss": 65,
    "stored_xss": 80,
    "dom_xss": 70,
    "csrf": 60,
    "clickjacking": 50,
    "sql_injection": 80,
    "prototype_pollution": 70,
    "insecure_deserialization": 75,
    "code_execution": 90,         # <-- IMPORTANT: category = malware (see TYPE_CATEGORY)
    "code_injection": 85,
    "race_condition": 40,
    "entropy_weakness": 30,
    "insecure_random": 30,
    "unencrypted_request": 25,
    "http_usage": 20,
    "remote_script_dependency": 50,
    "suspicious_network_request": 60,
    "hardcoded_credentials": 85,
    "hardcoded_api_token": 75,

    # Permission abuse
    "permission_overreach": 60,
    "tabs_access": 40,
    "history_access": 50,
    "clipboard_access": 50,
    "scripting_access": 60,
    "webrequest_surveillance": 70,
    "cookie_access": 50,
    "debugger_access": 95,
    "management_access": 80,
    "all_urls_access": 70,

    # PII & data abuse
    "password_harvesting": 90,
    "autofill_sniffing": 80,
    "form_data_exfiltration": 90,
    "behavioral_tracking": 40,
    "typing_fingerprint": 50,
    "token_theft": 90,
    "oauth_harvesting": 85,
    "jwt_harvesting": 85,
    "cross_site_tracking": 50,
    "referrer_harvesting": 40,

    # Obfuscation
    "base64_payload": 40,
    "hex_encoded_payload": 40,
    "string_splitting": 30,
    "eval_usage": 50,
    "suspicious_eval": 70,
    "function_constructor_execution": 70,
    "encrypted_inline_script": 70,
    "anti_debugging": 60,
    "minified_suspicious_code": 40,
    "source_map_removed": 20,

    # Supply chain risk
    "typosquatting": 70,
    "dependency_confusion": 80,
    "malicious_third_party": 75,
    "malicious_update": 85,
    "privilege_creep": 60,
    "fake_extension_identity": 80,
    "compromised_developer_account": 90,

    # Metadata & manifest issues
    "wildcard_url_match": 50,
    "missing_privacy_policy": 20,
    "csp_disabled": 60,
    "suspicious_domain": 50,
    "suspicious_ip": 50,
    "developer_id_change": 60,
    "multiple_domain_targets": 30,
}

# ============================================================
# CANONICAL TYPE → CATEGORY
# ============================================================

TYPE_CATEGORY: Dict[str, str] = {
    # Malware-ish behavior / payloads
    "adware": "malware",
    "spyware": "malware",
    "credential_stealer": "malware",
    "cookie_hijacking": "malware",
    "keylogger": "malware",
    "clipboard_hijacker": "malware",
    "session_hijacking": "malware",
    "dom_injection": "malware",
    "backdoor": "malware",
    "c2_communication": "malware",
    "payload_downloader": "malware",
    "polymorphic_script": "malware",
    "obfuscated_code": "malware",
    "self_modifying_script": "malware",
    "remote_code_loader": "malware",
    "cryptominer": "malware",
    "browser_hijacker": "malware",
    "search_hijacker": "malware",
    "redirect_injector": "malware",
    "phishing_script": "malware",
    "data_exfiltration": "malware",
    "tracking_beacon": "malware",
    "web_fingerprinting": "malware",
    "local_storage_theft": "malware",
    "indexeddb_sniffing": "malware",
    "code_execution": "malware",          # <-- FIXED: Trojan → code_execution → malware

    # Vulnerabilities
    "xss": "vulnerability",
    "reflected_xss": "vulnerability",
    "stored_xss": "vulnerability",
    "dom_xss": "vulnerability",
    "csrf": "vulnerability",
    "clickjacking": "vulnerability",
    "sql_injection": "vulnerability",
    "prototype_pollution": "vulnerability",
    "insecure_deserialization": "vulnerability",
    "code_injection": "vulnerability",
    "race_condition": "vulnerability",
    "entropy_weakness": "vulnerability",
    "insecure_random": "vulnerability",
    "unencrypted_request": "vulnerability",
    "http_usage": "vulnerability",
    "remote_script_dependency": "vulnerability",
    "suspicious_network_request": "vulnerability",
    "hardcoded_credentials": "vulnerability",
    "hardcoded_api_token": "vulnerability",

    # Permissions
    "permission_overreach": "permission",
    "tabs_access": "permission",
    "history_access": "permission",
    "clipboard_access": "permission",
    "scripting_access": "permission",
    "webrequest_surveillance": "permission",
    "cookie_access": "permission",
    "debugger_access": "permission",
    "management_access": "permission",
    "all_urls_access": "permission",
    "permission_escalation": "permission",

    # Privacy / data abuse
    "password_harvesting": "privacy",
    "autofill_sniffing": "privacy",
    "form_data_exfiltration": "privacy",
    "behavioral_tracking": "privacy",
    "typing_fingerprint": "privacy",
    "token_theft": "privacy",
    "oauth_harvesting": "privacy",
    "jwt_harvesting": "privacy",
    "cross_site_tracking": "privacy",
    "referrer_harvesting": "privacy",

    # Obfuscation
    "base64_payload": "obfuscation",
    "hex_encoded_payload": "obfuscation",
    "string_splitting": "obfuscation",
    "eval_usage": "obfuscation",
    "suspicious_eval": "obfuscation",
    "function_constructor_execution": "obfuscation",
    "encrypted_inline_script": "obfuscation",
    "anti_debugging": "obfuscation",
    "minified_suspicious_code": "obfuscation",
    "source_map_removed": "obfuscation",

    # Supply chain
    "typosquatting": "supply_chain",
    "dependency_confusion": "supply_chain",
    "malicious_third_party": "supply_chain",
    "malicious_update": "supply_chain",
    "privilege_creep": "supply_chain",
    "fake_extension_identity": "supply_chain",
    "compromised_developer_account": "supply_chain",

    # Metadata / manifest
    "wildcard_url_match": "metadata",
    "missing_privacy_policy": "metadata",
    "csp_disabled": "metadata",
    "suspicious_domain": "metadata",
    "suspicious_ip": "metadata",
    "developer_id_change": "metadata",
    "multiple_domain_targets": "metadata",
}

# ============================================================
# CANONICAL TYPE → REGEX PATTERNS
# ============================================================

TAG_PATTERNS: Dict[str, List[str]] = {
    # Malware & malicious behavior
    "adware": [
        r"\badware\b",
        r"\bpua(\b|:)",
        r"\bpotential(ly)? unwanted",
    ],
    "spyware": [
        r"\bspyware\b",
        r"\bspy\.",
        r"\bmonitor(ing)?\s+tool",
    ],
    "credential_stealer": [
        r"\b(cred(ential)?s?|password|pwd)\s*(steal(er)?|theft|grabber)",
        r"\bpwstealer\b",
        r"\bpws\b",
    ],
    "cookie_hijacking": [
        r"cookie(s)?\s*(theft|steal|hijack|grabber)",
        r"\bcookie\s*hijack",
    ],
    "keylogger": [
        r"\bkeylogger\b",
        r"key\s*log(ger|ging)",
    ],
    "clipboard_hijacker": [
        r"clipboard\s*(steal|hijack|sniff|logger)",
    ],
    "session_hijacking": [
        r"\bsession\s*hijack",
        r"\bsession\s*(theft|takeover)",
    ],
    "dom_injection": [
        r"\bdom\s*inject",
        r"\bhtml\s*inject",
    ],
    "backdoor": [
        r"\bbackdoor\b",
        r"\bbackdoor\.",
        r"\bremote\s*admin(istration)?\b",
    ],
    "c2_communication": [
        r"\bc2\b",
        r"command[-_ ]and[-_ ]control",
        r"\bcnc\b",
    ],
    "payload_downloader": [
        r"\bdownloader\b",
        r"\bdropper\b",
        r"\b(stage|second)[ -]?stage\b",
    ],
    "polymorphic_script": [
        r"\bpolymorph(ic|ism)\b",
    ],
    "obfuscated_code": [
        r"\bobfuscat(ed|ion)\b",
        r"atob\(",
        r"fromCharCode\(",
    ],
    "self_modifying_script": [
        r"\bself[-_ ]modif(y|ying)\b",
        r"eval\(.+eval\(",
    ],
    "remote_code_loader": [
        r"\bremote\s*(code|script)\s*(load|loader)",
    ],
    "cryptominer": [
        r"\bminer\b",
        r"\bcryptominer\b",
        r"\bcoinhive\b",
        r"\bmonero\b",
    ],
    "browser_hijacker": [
        r"browser\s*hijack",
        r"\bhijacker\b",
        r"home(page)?\s*hijack",
    ],
    "search_hijacker": [
        r"search\s*hijack",
        r"\bsearch\s*redirect",
    ],
    "redirect_injector": [
        r"\bredirect\b",
    ],
    "phishing_script": [
        r"\bphishing\b",
        r"\bfake\s*login",
        r"\blogin\s*page\s*clone",
    ],
    "data_exfiltration": [
        r"\bexfiltrat(e|ion)\b",
        r"\bdata\s*(leak|steal|theft)",
    ],
    "tracking_beacon": [
        r"\btracking\s*pixel",
        r"\bbeacon\b",
    ],
    "web_fingerprinting": [
        r"\bfingerprint(ing)?\b",
        r"canvas\s*fingerprint",
    ],
    "permission_escalation": [
        r"privilege\s*escalation",
        r"permission\s*escalation",
    ],
    "local_storage_theft": [
        r"localstorage",
    ],
    "indexeddb_sniffing": [
        r"\bindexeddb\b",
    ],

    # Vulnerabilities
    "xss": [
        r"\bxss\b",
        r"cross[- ]site\s*scripting",
    ],
    "reflected_xss": [
        r"reflected\s*xss",
    ],
    "stored_xss": [
        r"stored\s*xss",
        r"persistent\s*xss",
    ],
    "dom_xss": [
        r"\bdom[- ]based\s*xss",
    ],
    "csrf": [
        r"\bcsrf\b",
        r"cross[- ]site\s*request\s*forgery",
    ],
    "clickjacking": [
        r"\bclickjacking\b",
    ],
    "sql_injection": [
        r"sql\s*inject(ion)?",
        r"\bsqli\b",
    ],
    "prototype_pollution": [
        r"prototype\s*pollution",
        r"__proto__",
    ],
    "insecure_deserialization": [
        r"insecure\s*deserializ",
    ],
    "code_execution": [
        r"remote\s*code\s*execution",
        r"\brce\b",
        r"\btrojan\b",   # Trojan → type=code_execution → category=malware
    ],
    "code_injection": [
        r"code\s*inject(ion)?",
        r"script\s*inject(ion)?",
    ],
    "race_condition": [
        r"race\s*condition",
    ],
    "entropy_weakness": [
        r"low\s*entropy",
        r"predictable\s*random",
    ],
    "insecure_random": [
        r"insecure\s*random",
    ],
    "unencrypted_request": [
        r"\bhttp://",
        r"unencrypted\s*request",
    ],
    "http_usage": [
        r"\bhttp://",
    ],
    "remote_script_dependency": [
        r"\bcdn\b",
    ],
    "suspicious_network_request": [
        r"\bfetch\(",
        r"\bxmlhttprequest\b",
    ],
    "hardcoded_credentials": [
        r"password",
    ],
    "hardcoded_api_token": [
        r"\bapi[_-]?token\b",
        r"bearer\s+[A-Za-z0-9_\-]{10,}",
    ],

    # Permission abuse
    "permission_overreach": [
        r"permissions?\b",
    ],
    "tabs_access": [
        r"\btabs\b",
        r"\btabs?_permission\b",
    ],
    "history_access": [
        r"\bhistory\b",
    ],
    "clipboard_access": [
        r"\bclipboard\b",
    ],
    "scripting_access": [
        r"\bscripting\b",
        r"\bscripting_permission\b",
    ],
    "webrequest_surveillance": [
        r"webrequest",
        r"onbeforerequest",
    ],
    "cookie_access": [
        r"\bcookies?\b",
    ],
    "debugger_access": [
        r"\bdebugger\b",
    ],
    "management_access": [
        r"\bmanagement\b",
    ],
    "all_urls_access": [
        r"\ball_urls_access\b",
        r"<all_urls>",
        r"\*://\*/\*",
    ],

    # PII & data abuse
    "password_harvesting": [
        r"password",
        r"pwd",
    ],
    "autofill_sniffing": [
        r"autofill",
    ],
    "form_data_exfiltration": [
        r"form\s*data",
    ],
    "behavioral_tracking": [
        r"analytics",
        r"telemetry",
    ],
    "typing_fingerprint": [
        r"typing\s*pattern",
        r"keypress",
    ],
    "token_theft": [
        r"\btoken\b",
    ],
    "oauth_harvesting": [
        r"\boauth\b",
    ],
    "jwt_harvesting": [
        r"\bjwt\b",
    ],
    "cross_site_tracking": [
        r"cross[- ]site\s*tracking",
    ],
    "referrer_harvesting": [
        r"\breferrer\b",
    ],

    # Obfuscation
    "base64_payload": [
        r"base64",
    ],
    "hex_encoded_payload": [
        r"(0x[0-9a-fA-F]{2}){4,}",
    ],
    "string_splitting": [
        r"[\"'][A-Za-z0-9]{2,}[\"']\s*\+\s*[\"'][A-Za-z0-9]{2,}[\"']",
    ],
    "eval_usage": [
        r"\beval\(",
    ],
    "suspicious_eval": [
        r"eval\(\s*(atob|unescape|function|window\[)",
    ],
    "function_constructor_execution": [
        r"\bnew\s+function\(",
    ],
    "encrypted_inline_script": [
        r"decrypt\(",
    ],
    "anti_debugging": [
        r"devtools",
        r"debugger;",
    ],
    "minified_suspicious_code": [
        r"[a-zA-Z0-9_$]{1,2}=function\(",
    ],
    "source_map_removed": [
        r"//# sourceMappingURL",
    ],

    # Supply chain risk
    "typosquatting": [
        r"(typo|squat)ting",
    ],
    "dependency_confusion": [
        r"dependency\s*confusion",
    ],
    "malicious_third_party": [
        r"third[- ]party",
    ],
    "malicious_update": [
        r"auto[- ]update",
    ],
    "privilege_creep": [
        r"new\s*permissions",
    ],
    "fake_extension_identity": [
        r"fake\s*extension",
        r"impersonat(ion|e)",
    ],
    "compromised_developer_account": [
        r"compromised\s*developer",
        r"account\s*takeover",
    ],

    # Metadata & manifest issues
    "wildcard_url_match": [
        r"<all_urls>",
        r"\*://\*/\*",
    ],
    "missing_privacy_policy": [
        r"privacy\s*policy",
    ],
    "csp_disabled": [
        r"content[- ]security[- ]policy",
        r"unsafe-inline",
    ],
    "suspicious_domain": [
        r"\b(onion|darkweb|btc|monero)\b",
    ],
    "suspicious_ip": [
        r"\b\d{1,3}(\.\d{1,3}){3}\b",
    ],
    "developer_id_change": [
        r"developer\s*id\s*change",
        r"publisher\s*changed",
    ],
    "multiple_domain_targets": [
        r"\b(domains?|hosts?)\b",
    ],
}

# ============================================================
# HELPERS
# ============================================================

def _normalize_label(label: str) -> str:
    """Normalize 'HEUR:Trojan.Script.Generic' -> 'heur_trojan_script_generic'."""
    normalized = re.sub(r"[^a-zA-Z0-9]+", "_", label)
    return normalized.strip("_").lower()


def _collect_candidates_by_name(normalized_label: str) -> Dict[str, Set[str]]:
    """
    Use normalized label to guess types by name.
    Returns { type: {tags} }.
    """
    candidates: Dict[str, Set[str]] = {}

    for t in TAG_SCORES.keys():
        if normalized_label == t or t in normalized_label:
            candidates.setdefault(t, set()).add(normalized_label)

    # Special aliases and heuristics
    if "all_urls" in normalized_label:
        candidates.setdefault("all_urls_access", set()).add(normalized_label)

    if "scripting" in normalized_label:
        candidates.setdefault("scripting_access", set()).add(normalized_label)

    if "tabs" in normalized_label:
        candidates.setdefault("tabs_access", set()).add(normalized_label)

    if "history" in normalized_label:
        candidates.setdefault("history_access", set()).add(normalized_label)

    return candidates


def _collect_candidates_by_regex(label: str) -> Dict[str, Set[str]]:
    """
    Run regex patterns over raw label.
    Returns { type: {matched_substrings} }.
    """
    text = label.lower()
    candidates: Dict[str, Set[str]] = {}

    for t, patterns in TAG_PATTERNS.items():
        for pat in patterns:
            try:
                m = re.search(pat, text)
            except re.error:
                # Bad pattern won't crash everything.
                continue
            if m:
                matched = m.group(0)
                if matched:
                    candidates.setdefault(t, set()).add(matched)

    return candidates


def _pick_best_type(candidates: Dict[str, Set[str]]) -> Tuple[str, str]:
    """
    Given {type: {tags}}, pick the highest scoring type
    and one 'tag' (prefer shortest string).
    Returns (type, tag).
    """
    if not candidates:
        return None, None

    best_type = max(candidates.keys(), key=lambda t: TAG_SCORES.get(t, 0))

    tag_candidates = list(candidates[best_type]) or [best_type]
    tag_candidates.sort(key=len)
    best_tag = tag_candidates[0]

    return best_type, best_tag


# ============================================================
# PUBLIC API
# ============================================================

def analyze_label(label: str) -> Dict[str, Any]:
    """
    Analyze VirusTotal/OPSWAT-style label and return:

        {
            "tag": <specific matched term>,
            "type": <canonical type>,
            "category": <broad category>,
            "score": <0-100>
        }

    If nothing matches, returns safe default.
    """
    if not isinstance(label, str) or not label.strip():
        return {"tag": None, "type": None, "category": "unknown", "score": 0}

    normalized = _normalize_label(label)

    candidates: Dict[str, Set[str]] = {}

    name_candidates = _collect_candidates_by_name(normalized)
    for t, tags in name_candidates.items():
        candidates.setdefault(t, set()).update(tags)

    regex_candidates = _collect_candidates_by_regex(label)
    for t, tags in regex_candidates.items():
        candidates.setdefault(t, set()).update(tags)

    best_type, best_tag = _pick_best_type(candidates)

    if best_type is None:
        return {"tag": None, "type": None, "category": "unknown", "score": 0}

    score = TAG_SCORES.get(best_type, 0)
    category = TYPE_CATEGORY.get(best_type, "unknown")

    if best_tag is not None:
        best_tag = best_tag.strip().lower()

    return {
        "tag": best_tag,
        "type": best_type,
        "category": category,
        "score": score,
    }


from typing import Any, Dict, List, Optional


HIGH_RISK_PERMISSIONS = {
    "tabs",
    "history",
    "bookmarks",
    "cookies",
    "downloads",
    "webRequest",
    "webRequestBlocking",
    "background",
    "nativeMessaging",
    "management",
    "clipboardRead",
    "clipboardWrite",
    "storage",
    "host_permissions_all",  # you can map "<all_urls>" to this
}

SUSPICIOUS_BEHAVIOR_KEYWORDS = [
    "keylog",
    "key logger",
    "screenshot",
    "steal",
    "exfiltrat",
    "command and control",
    "c2",
    "inject",
    "injection",
    "persistence",
    "autorun",
    "registry",
    "startup",
    "crypto",
    "miner",
    "ransom",
    "obfuscat",
    "pack",
    "encode",
]

NETWORK_BEHAVIOR_KEYWORDS = [
    "http",
    "https",
    "socket",
    "dns",
    "beacon",
    "post request",
    "get request",
    "upload",
    "download",
    "remote server",
]

FILE_BEHAVIOR_KEYWORDS = [
    "create file",
    "modify file",
    "delete file",
    "write file",
    "read file",
    "temp folder",
    "system32",
]


def _safe_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _classify_risk(score: Optional[float], verdict: Optional[str]) -> str:
    verdict = (verdict or "").lower()

    if "malic" in verdict:
        return "high"
    if "susp" in verdict:
        return "medium"
    if "clean" in verdict or "benign" in verdict:
        return "low"

    if score is None:
        return "unknown"

    try:
        s = float(score)
    except Exception:
        return "unknown"

    if s >= 80:
        return "high"
    if s >= 40:
        return "medium"
    return "low"


def _summarize_permissions(permissions: List[str]) -> str:
    if not permissions:
        return "No explicit permissions were listed."

    perms_lower = [p.lower() for p in permissions]
    high_risk = []
    normal = []

    for p in perms_lower:
        if "<all_urls>" in p:
            high_risk.append("access to all visited websites (<all_urls>)")
            continue

        key = p.split(".")[-1]  # handle things like chrome.permissions style
        if key in (hp.lower() for hp in HIGH_RISK_PERMISSIONS):
            high_risk.append(p)
        else:
            normal.append(p)

    parts = []
    parts.append(f"The extension requests {len(permissions)} permission(s).")

    if high_risk:
        parts.append(
            "High-risk or sensitive permissions include: "
            + ", ".join(sorted(set(high_risk))) + "."
        )

    if normal:
        parts.append(
            "Other permissions: " + ", ".join(sorted(set(normal))) + "."
        )

    return " ".join(parts)


def _summarize_findings(findings: List[str]) -> str:
    if not findings:
        return "No specific findings were provided."
    if len(findings) == 1:
        return f"Single notable finding: {findings[0]}"
    return (
        f"{len(findings)} findings were reported, including: "
        + "; ".join(findings[:5])
        + ("." if len(findings) <= 5 else " ...")
    )


def _detect_behavior_flags(behaviour_text: str) -> Dict[str, bool]:
    text = behaviour_text.lower()
    flags = {
        "suspicious": False,
        "network": False,
        "file_system": False,
    }

    if any(k in text for k in SUSPICIOUS_BEHAVIOR_KEYWORDS):
        flags["suspicious"] = True
    if any(k in text for k in NETWORK_BEHAVIOR_KEYWORDS):
        flags["network"] = True
    if any(k in text for k in FILE_BEHAVIOR_KEYWORDS):
        flags["file_system"] = True

    return flags


def _build_extension_summary(
    findings: List[str],
    behaviour_text: str,
    score: Optional[float],
    verdict: Optional[str],
    permissions: List[str],
    extension_id: Optional[str],
) -> str:
    verdict_norm = _normalize_text(verdict)
    extension_id_norm = _normalize_text(extension_id) or "unknown"

    risk_level = _classify_risk(score, verdict_norm)
    perms_summary = _summarize_permissions(permissions)
    findings_summary = _summarize_findings(findings)
    behavior_flags = _detect_behavior_flags(behaviour_text)

    lines = []

    lines.append(
        f"Extension ID: {extension_id_norm}. Based on the provided score and verdict, "
        f"the overall risk level is assessed as {risk_level.upper()}."
    )

    if verdict_norm:
        lines.append(f"Reported verdict: {verdict_norm}.")

    lines.append(findings_summary)
    lines.append(perms_summary)

    if behavior_flags["suspicious"]:
        lines.append(
            "The reported behavior contains patterns typically associated with malicious activity "
            "(such as persistence, injection, credential theft, or data exfiltration)."
        )
    else:
        lines.append(
            "No strongly characteristic malware behavior was clearly identified in the behavior text, "
            "though the analysis is limited to the provided data."
        )

    if behavior_flags["network"]:
        lines.append(
            "The extension appears to perform network communication, which may be legitimate "
            "but could also be used for tracking or command-and-control if misused."
        )

    if behavior_flags["file_system"]:
        lines.append(
            "There are indications of file-system interaction (creating, modifying, or deleting files), "
            "which may be part of normal operation or a sign of tampering depending on context."
        )

    lines.append(
        "Overall, this summary is heuristic and based only on the provided score, verdict, findings, "
        "permissions, and behavior text; no external reputation lookup was performed."
    )

    return " ".join(lines)


def _build_file_behavior_summary(
    findings: List[str],
    behaviour_text: str,
) -> str:
    if not behaviour_text and not findings:
        return (
            "No detailed behavior report was provided. The runtime behavior of the file/extension "
            "cannot be described beyond noting a lack of observable data."
        )

    flags = _detect_behavior_flags(behaviour_text)
    lines = []

    if behaviour_text:
        lines.append(
            "Observed behavior (as reported): "
            + behaviour_text.strip().replace("\n", " ")
        )

    if findings:
        if len(findings) == 1:
            lines.append(f"The analysis reported one key finding: {findings[0]}.")
        else:
            lines.append(
                f"The analysis reported {len(findings)} findings relevant to behavior, "
                "such as: " + "; ".join(findings[:5]) + ("" if len(findings) <= 5 else " ...")
            )

    if flags["network"]:
        lines.append(
            "Behavior includes network-related actions (e.g. HTTP requests or remote connections), "
            "which may indicate communication with external services or servers."
        )

    if flags["file_system"]:
        lines.append(
            "Behavior includes operations on the file system (creating, modifying, or deleting files), "
            "which may indicate logging, configuration storage, or tampering."
        )

    if flags["suspicious"]:
        lines.append(
            "Some described actions are characteristic of potentially malicious software, such as "
            "persistence mechanisms, data theft, or code injection. These should be treated as high-risk."
        )
    else:
        lines.append(
            "No clearly malicious runtime pattern is evident from the provided text, but this does not "
            "guarantee that the extension or file is safe."
        )

    return " ".join(lines)


def offline_analysis_from_components(
    findings: Any,
    behaviour: Any,
    score: Optional[float] = None,
    verdict: Optional[str] = None,
    permissions: Optional[Any] = None,
    extension_id: Optional[str] = None,
) -> Dict[str, Any]:
    findings_list = [str(f) for f in _safe_list(findings)]
    behaviour_text = _normalize_text(behaviour)
    permissions_list = [str(p) for p in _safe_list(permissions)]

    try:
        extension_summary = _build_extension_summary(
            findings=findings_list,
            behaviour_text=behaviour_text,
            score=score,
            verdict=verdict,
            permissions=permissions_list,
            extension_id=extension_id,
        )
    except Exception as e:
        extension_summary = (
            f"Failed to build a detailed extension summary due to an internal error: {e}. "
            "Only minimal information is available."
        )

    try:
        file_behavior_summary = _build_file_behavior_summary(
            findings=findings_list,
            behaviour_text=behaviour_text,
        )
    except Exception as e:
        file_behavior_summary = (
            f"Failed to build a detailed file behavior summary due to an internal error: {e}. "
            "Behavior cannot be described further."
        )

    return {
        "extension_id": extension_id,
        "extension_summary": extension_summary,
        "file_behavior_summary": file_behavior_summary,
    }

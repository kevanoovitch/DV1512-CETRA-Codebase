
import re
from typing import List


GENERIC = {
    "heur", "trojan", "script", "generic", "malware", "virus",
    "win32", "w32", "msil", "agent", "variant", "worm", "packed"
}


def _normalize(label: str) -> str | None:
    if not label:
        return None

    l = label.lower()

    if ":" in l:
        l = l.split(":", 1)[1]

    parts = re.split(r"[^a-z0-9]+", l)
    parts = [p for p in parts if p]

    meaningful = [p for p in parts if p not in GENERIC and len(p) > 2]

    if not meaningful:
        return None

    return meaningful[0]


def infer_attribution(labels: List[str]) -> list | None:
    fams = []

    for lbl in labels:
        fam = _normalize(lbl)
        if fam and fam not in fams:
            fams.append(fam)

    fams = fams[:2]  # limit to 2 families max

    if not fams:
        return None

    # Always append campaign placeholder
    fams.append("unknown-campaign")

    return fams

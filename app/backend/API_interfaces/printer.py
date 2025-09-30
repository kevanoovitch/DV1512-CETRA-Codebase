# helpers/pretty_print.py
from typing import Dict, Any, List, Tuple
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()

def map_score_to_verdict(score: int) -> Tuple[str, str]:
    """
    Map numeric score to (verdict, color).
    """
    if score >= 80:
        return "malicious", "red"
    if score >= 60:
        return "high_risk", "dark_orange3"
    if score >= 40:
        return "suspicious", "yellow3"
    if score >= 20:
        return "low", "green3"
    return "minimal", "cyan"

def pretty_print_sa_result(parsed: Dict[str, Any], top_n: int = 8) -> None:
    """
    Pretty print the parsed SA output: verdict panel + top findings table.
    `parsed` is what your interpreter returns: {"score": int, "findings": [...]}
    """
    score: int = int(parsed.get("score", 0))
    findings: List[Dict[str, Any]] = parsed.get("findings", [])

    verdict, color = map_score_to_verdict(score)

    # Verdict panel
    title = Text(f" Secure Annex Verdict: {verdict.upper()} ", style=f"bold {color}")
    body = Text()
    body.append(f"Score: ", style="bold")
    body.append(f"{score}/100\n", style=f"{color}")
    body.append("Interpretation: ", style="bold")
    interp = {
        "malicious": "Block immediately; evidence strongly indicates harmful capability/behavior.",
        "high_risk": "Very risky permission set or behavior; block or sandbox.",
        "suspicious": "Concerning signals present; review before allowing.",
        "low": "Some risk indicators; generally acceptable with caution.",
        "minimal": "No strong indicators observed; still not a guarantee of safety.",
    }[verdict]
    body.append(interp)

    console.print(Panel(body, title=title, border_style=color))

    # Findings table
    if not findings:
        console.print("[dim]No findings to display.[/dim]")
        return

    table = Table(
        title="Top Findings",
        title_style="bold",
        show_lines=False,
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
    )
    table.add_column("Source", no_wrap=True)
    table.add_column("Risk Type", no_wrap=True)
    table.add_column("Severity", justify="right", no_wrap=True)
    table.add_column("Points", justify="right", no_wrap=True)
    table.add_column("Description", overflow="fold")

    # Sort by points desc, then severity desc
    def _sev(x): 
        v = x.get("severity")
        try: return int(v) if v is not None else -1
        except: return -1

    sorted_findings = sorted(
        (as_dict(f) for f in findings),
        key=lambda f: (int(f.get("points", 0)), _sev(f)),
        reverse=True,
    )[:top_n]

    for f in sorted_findings:
        sev = f.get("severity")
        sev_str = "-" if sev is None else str(sev)
        pts = str(f.get("points", 0))

        # Light color hint per source
        src_style = {
            "manifest": "magenta",
            "signatures": "blue",
            "urls": "cyan",
            "analysis": "yellow",
        }.get(f.get("source", ""), "white")

        table.add_row(
            f"[{src_style}]{f.get('source','')}[/]",
            f.get("risk_type", ""),
            sev_str,
            pts,
            f.get("description", ""),
        )

    console.print(table)

def as_dict(finding_obj: Any) -> Dict[str, Any]:
    """
    Convert your Finding dataclass (or plain dict) to a dict for printing.
    """
    if isinstance(finding_obj, dict):
        return finding_obj
    # dataclass or object with attributes
    out = {}
    for key in ("source", "risk_type", "severity", "description", "points", "extra"):
        out[key] = getattr(finding_obj, key, None)
    return out

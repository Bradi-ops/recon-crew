# =============================================================================
# ReconCrew v3 - Report Generator
# =============================================================================

import json
import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from config import OUTPUT_DIR


def generate_report(report_data: dict, target_url: str, duration_seconds: float) -> str:
    """Generate HTML report from structured data. Returns filepath."""
    findings = report_data.get("findings", [])

    # Calculate stats
    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0, "pages_crawled": "N/A"}
    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev in stats:
            stats[sev] += 1
        stats["total"] += 1

    if "statistics" in report_data:
        stats["pages_crawled"] = report_data["statistics"].get("pages_crawled", "N/A")

    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: sev_order.get(f.get("severity", "info").lower(), 5))

    minutes = int(duration_seconds // 60)
    seconds = int(duration_seconds % 60)
    duration_str = f"{minutes}m {seconds}s" if minutes else f"{seconds}s"

    # Find template
    template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
    if not os.path.exists(os.path.join(template_dir, "report.html")):
        template_dir = os.path.join(os.path.dirname(__file__), "templates")
    if not os.path.exists(os.path.join(template_dir, "report.html")):
        template_dir = "./templates"

    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template("report.html")

    html = template.render(
        target=target_url,
        scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        duration=duration_str,
        stats=stats,
        executive_summary=report_data.get("executive_summary", "No summary."),
        technologies=report_data.get("technologies", []),
        findings=findings,
        next_steps=report_data.get("next_steps", []),
    )

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    sanitized = target_url.replace("https://", "").replace("http://", "").replace("/", "_").rstrip("_")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(OUTPUT_DIR, f"recon_{sanitized}_{ts}.html")

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    # Also save JSON
    json_path = filepath.replace(".html", ".json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)

    return filepath

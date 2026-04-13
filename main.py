#!/usr/bin/env python3
# =============================================================================
# ReconCrew v3.1 - Agentic Web Reconnaissance
# =============================================================================
# Agents make real decisions:
#   - Spider Agent:   chooses crawl depth, identifies extra paths to check
#   - JS Agent:       decides which JS files matter, prioritizes findings
#   - Secrets Agent:  takes Spider's extra paths, probes additional files
#   - Forms Agent:    triages form issues by exploitability
#   - Endpoint Prober:   picks tech-specific endpoints, analyzes access control
#   - Coordinator:    synthesizes everything into final report
#
# Every decision has a fallback. If LLM fails, scan continues with defaults.
# =============================================================================

import sys
import os
import json
import time
import argparse
import warnings
from urllib.parse import urlparse
from datetime import datetime

warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.dirname(__file__))

from config import OUTPUT_DIR
from llm_client import check_llm_connection

BANNER = r"""
╔══════════════════════════════════════════════════════╗
║   ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗       ║
║   ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║       ║
║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║       ║
║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║       ║
║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║       ║
║   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝       ║
║            ██████╗██████╗ ███████╗██╗    ██╗         ║
║           ██╔════╝██╔══██╗██╔════╝██║    ██║         ║
║           ██║     ██████╔╝█████╗  ██║ █╗ ██║         ║
║           ██║     ██╔══██╗██╔══╝  ██║███╗██║         ║
║           ╚██████╗██║  ██║███████╗╚███╔███╔╝         ║
║            ╚═════╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝         ║
║                                                      ║
║   Agentic Web Reconnaissance  v3.1                   ║
║   For authorized security testing only               ║
╚══════════════════════════════════════════════════════╝
"""


def run_agent(name, agent, *args):
    """Run an agent with timing."""
    print(f"\n{'='*60}")
    print(f"[*] Agent: {name}")
    print(f"{'='*60}")
    start = time.time()
    try:
        result = agent.run(*args)
        elapsed = time.time() - start
        findings = len(result.get("analysis", {}).get("findings", []))
        print(f"[+] {name} completed in {elapsed:.1f}s — {findings} findings")
        return result
    except Exception as e:
        print(f"[!] {name} failed: {e}")
        import traceback
        traceback.print_exc()
        return {"tool_data": None, "analysis": {"findings": [], "notes": f"Failed: {e}"}}


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="ReconCrew v3.1")
    parser.add_argument("target", help="Target URL")
    parser.add_argument("--skip-probe", action="store_true")
    parser.add_argument("--skip-ai", action="store_true")
    args = parser.parse_args()

    target = args.target
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    print(f"[*] Target: {target}\n")

    if not args.skip_ai:
        if not check_llm_connection():
            print("[!] LLM not available. Use --skip-ai for tool-only mode.")
            sys.exit(1)
        print()

    confirm = input("[?] Launch scan? (y/N): ").strip().lower()
    if confirm != "y":
        sys.exit(0)

    start_time = time.time()

    from agents import SpiderAgent, JSAgent, SecretsAgent, FormsAgent, ProberAgent, CoordinatorAgent

    # ============================
    # Phase 1: Spider
    # ============================
    spider_result = run_agent("Spider Agent", SpiderAgent(), target)
    spider_data = spider_result.get("tool_data")

    if not spider_data:
        print("[!] Spider failed, cannot continue.")
        sys.exit(1)

    extra_paths = spider_result.get("extra_paths", [])

    # ============================
    # Phase 2: JS Analysis
    # ============================
    js_files = spider_data.get("js_files", [])
    target_domain = urlparse(target).netloc
    js_result = run_agent("JS Agent", JSAgent(), js_files, target_domain)
    js_data = js_result.get("tool_data", [])

    # Collect endpoints for prober
    js_endpoints = []
    if js_data:
        for f in js_data:
            if isinstance(f, dict):
                for ep in f.get("endpoints", []):
                    val = ep.get("value", "")
                    if val:
                        js_endpoints.append(val)

    # ============================
    # Phase 3: Secrets (receives extra paths from Spider Agent)
    # ============================
    secrets_result = run_agent("Secrets Agent", SecretsAgent(), target, extra_paths)

    # ============================
    # Phase 4: Forms
    # ============================
    forms = spider_data.get("forms", [])
    forms_result = run_agent("Forms Agent", FormsAgent(), forms)

    # ============================
    # Phase 5: Probing
    # ============================
    probe_result = {"tool_data": [], "analysis": {"findings": [], "notes": "Skipped"}}
    if not args.skip_probe:
        techs = spider_data.get("technologies_detected", [])
        probe_result = run_agent("Endpoint Prober", ProberAgent(), target, js_endpoints, techs)

    duration = time.time() - start_time

    # ============================
    # Save raw data
    # ============================
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    raw_path = os.path.join(OUTPUT_DIR, f"raw_{urlparse(target).netloc}_{datetime.now():%Y%m%d_%H%M%S}.json")
    raw = {
        "spider": spider_data, "js": js_data or [],
        "secrets": secrets_result.get("tool_data", []),
        "forms": forms_result.get("tool_data", []),
        "probe": probe_result.get("tool_data", []),
    }
    with open(raw_path, "w") as f:
        json.dump(raw, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Raw data: {raw_path}")

    # ============================
    # Phase 6: Coordinator
    # ============================
    all_results = {
        "spider": spider_result, "js": js_result,
        "secrets": secrets_result, "forms": forms_result,
        "probe": probe_result,
    }

    print(f"\n{'='*60}")
    print(f"[*] Agent: Coordinator")
    print(f"{'='*60}")

    if args.skip_ai:
        all_findings = []
        for r in all_results.values():
            all_findings.extend(r.get("analysis", {}).get("findings", []))
        report = {
            "executive_summary": f"Scan of {target}. {len(all_findings)} findings.",
            "technologies": spider_data.get("technologies_detected", []),
            "findings": all_findings,
            "statistics": {"pages_crawled": len(spider_data.get("pages", []))},
            "next_steps": ["Manual testing", "WPScan", "Auth testing"],
        }
    else:
        start = time.time()
        coordinator = CoordinatorAgent()
        report = coordinator.run(target, {k: v for k, v in all_results.items()}, duration)
        print(f"[+] Coordinator done in {time.time()-start:.1f}s")

    # ============================
    # HTML Report
    # ============================
    from report_generator import generate_report
    report_path = generate_report(report, target, duration)
    print(f"[+] HTML report: {report_path}")

    total = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"[+] Completed in {int(total//60)}m {int(total%60)}s")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()

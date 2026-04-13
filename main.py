#!/usr/bin/env python3
# =============================================================================
# ReconCrew v3 - Semi-Agentic Web Reconnaissance
# =============================================================================
# Each phase: Tool runs → Agent analyzes results with LLM
# If LLM fails at any point, fallback to raw data. Scan never breaks.
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
║   Semi-Agentic Web Reconnaissance  v3                ║
║   For authorized security testing only               ║
╚══════════════════════════════════════════════════════╝
"""


def run_phase(name, tool_func, agent_func, tool_args, agent_args_from_tool=None):
    """
    Run a phase: execute tool, then have agent analyze results.
    Returns (tool_data, agent_analysis).
    """
    print(f"\n{'='*60}")
    print(f"[*] Phase: {name}")
    print(f"{'='*60}")

    # Step 1: Run tool
    start = time.time()
    print(f"[*] Running tool...")
    try:
        tool_data = tool_func(*tool_args)
        tool_time = time.time() - start
        print(f"[+] Tool completed in {tool_time:.1f}s")
    except Exception as e:
        print(f"[!] Tool failed: {e}")
        import traceback
        traceback.print_exc()
        return None, {"findings": [], "notes": f"Tool failed: {e}"}

    # Step 2: Agent analyzes
    print(f"[*] Agent analyzing...")
    start = time.time()
    try:
        if agent_args_from_tool:
            agent_input = agent_args_from_tool(tool_data)
        else:
            agent_input = tool_data
        analysis = agent_func(agent_input)
        agent_time = time.time() - start
        print(f"[+] Agent done in {agent_time:.1f}s")
    except Exception as e:
        print(f"[!] Agent failed: {e}")
        analysis = {"findings": [], "notes": f"Agent failed: {e}"}

    return tool_data, analysis


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="ReconCrew v3")
    parser.add_argument("target", help="Target URL")
    parser.add_argument("--skip-fuzz", action="store_true")
    parser.add_argument("--skip-ai", action="store_true", help="Skip all LLM analysis")
    args = parser.parse_args()

    target = args.target
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    print(f"[*] Target: {target}\n")

    # Check LLM
    if not args.skip_ai:
        if not check_llm_connection():
            print("[!] LLM not available. Use --skip-ai for basic scan.")
            sys.exit(1)
        print()

    confirm = input("[?] Launch scan? (y/N): ").strip().lower()
    if confirm != "y":
        sys.exit(0)

    start_time = time.time()

    # Import here to avoid config issues
    from tools import web_spider, js_analyzer, secrets_scanner, form_analyzer, endpoint_fuzzer
    from agents import (agent_spider_analyze, agent_js_analyze, agent_secrets_analyze,
                        agent_forms_analyze, agent_fuzz_analyze, agent_coordinator)

    # Dummy agent for --skip-ai mode
    def no_agent(data):
        findings = []
        if isinstance(data, dict):
            for tech in data.get("technologies_detected", []):
                findings.append({"title": f"Technology: {tech}", "severity": "info",
                                 "category": "information_disclosure", "description": tech,
                                 "evidence": tech, "recommendation": "Keep updated"})
        return {"findings": findings, "notes": "AI analysis skipped"}

    spider_agent = no_agent if args.skip_ai else agent_spider_analyze
    js_agent_fn = no_agent if args.skip_ai else agent_js_analyze
    secrets_agent = no_agent if args.skip_ai else agent_secrets_analyze
    forms_agent = no_agent if args.skip_ai else agent_forms_analyze
    fuzz_agent = no_agent if args.skip_ai else agent_fuzz_analyze

    # ============================
    # Phase 1: Spider
    # ============================
    spider_data, spider_analysis = run_phase(
        "Web Spider",
        web_spider, spider_agent,
        tool_args=(target,),
    )

    if not spider_data:
        print("[!] Spider failed, cannot continue.")
        sys.exit(1)

    # Print spider summary
    print(f"    ├─ Pages:    {len(spider_data.get('pages', []))}")
    print(f"    ├─ JS files: {len(spider_data.get('js_files', []))}")
    print(f"    ├─ Forms:    {len(spider_data.get('forms', []))}")
    print(f"    ├─ Comments: {len(spider_data.get('comments', []))}")
    print(f"    └─ Tech:     {', '.join(spider_data.get('technologies_detected', []))}")

    # ============================
    # Phase 2: JS Analysis
    # ============================
    js_files = spider_data.get("js_files", [])
    target_js = [f for f in js_files
                 if not any(skip in f for skip in ["jquery", "cloudflare", "cdn.", "googleapis",
                                                    "gstatic", "wp-includes", "wp-emoji"])]
    print(f"\n[*] JS: {len(js_files)} total, {len(target_js)} target-specific")

    js_data, js_analysis = run_phase(
        "JS Analysis",
        js_analyzer, js_agent_fn,
        tool_args=(target_js,) if target_js else ([], ),
    )

    if js_data:
        total_ep = sum(len(f.get("endpoints", [])) for f in js_data if isinstance(f, dict))
        total_sec = sum(len(f.get("secrets", [])) for f in js_data if isinstance(f, dict))
        print(f"    ├─ Endpoints: {total_ep}")
        print(f"    └─ Secrets:   {total_sec}")

    # ============================
    # Phase 3: Secrets
    # ============================
    secrets_data, secrets_analysis = run_phase(
        "Secrets Scanner",
        secrets_scanner, secrets_agent,
        tool_args=(target,),
    )

    if secrets_data:
        accessible = len([s for s in secrets_data if s.get("status") == 200])
        forbidden = len([s for s in secrets_data if s.get("status") == 403])
        print(f"    ├─ Accessible: {accessible}")
        print(f"    └─ Forbidden:  {forbidden}")

    # ============================
    # Phase 4: Forms
    # ============================
    forms = spider_data.get("forms", [])
    forms_data, forms_analysis = run_phase(
        "Form Analysis",
        form_analyzer, forms_agent,
        tool_args=(forms,),
    )
    if forms_data:
        print(f"    └─ Forms with issues: {len(forms_data)}")

    # ============================
    # Phase 5: Fuzzing
    # ============================
    fuzz_data = []
    fuzz_analysis = {"findings": [], "notes": "Skipped"}

    if not args.skip_fuzz:
        endpoints = set()
        if js_data:
            for f in js_data:
                if isinstance(f, dict):
                    for ep in f.get("endpoints", []):
                        endpoints.add(ep.get("value", ""))

        # WP endpoints
        wp_eps = ["/wp-json/wp/v2/users", "/wp-json/wp/v2/posts", "/wp-json/",
                  "/wp-admin/", "/wp-login.php", "/wp-content/debug.log",
                  "/xmlrpc.php", "/wp-cron.php", "/?rest_route=/wp/v2/users"]
        endpoints.update(wp_eps)
        endpoints.discard("")

        fuzz_data, fuzz_analysis = run_phase(
            "Endpoint Fuzzer",
            endpoint_fuzzer, fuzz_agent,
            tool_args=(target.rstrip("/"), list(endpoints)),
        )

        if fuzz_data:
            by_status = {}
            for r in fuzz_data:
                s = r.get("status", "?")
                by_status[s] = by_status.get(s, 0) + 1
            for status, count in sorted(by_status.items()):
                print(f"    ├─ HTTP {status}: {count}")
            print(f"    └─ Total: {len(fuzz_data)}")

    duration = time.time() - start_time

    # ============================
    # Save raw data
    # ============================
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    raw_path = os.path.join(OUTPUT_DIR, f"raw_{urlparse(target).netloc}_{datetime.now():%Y%m%d_%H%M%S}.json")
    raw_data = {
        "spider": spider_data, "js_analysis": js_data or [],
        "secrets": secrets_data or [], "forms_analysis": forms_data or [],
        "fuzz": fuzz_data or [],
    }
    with open(raw_path, "w") as f:
        json.dump(raw_data, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Raw data: {raw_path}")

    # ============================
    # Phase 6: Coordinator
    # ============================
    print(f"\n{'='*60}")
    print(f"[*] Phase: Coordinator Report")
    print(f"{'='*60}")

    all_agent_results = {
        "spider": spider_analysis,
        "js": js_analysis,
        "secrets": secrets_analysis,
        "forms": forms_analysis,
        "fuzz": fuzz_analysis,
    }

    if args.skip_ai:
        # Assemble basic report
        all_findings = []
        for r in all_agent_results.values():
            all_findings.extend(r.get("findings", []))
        report = {
            "executive_summary": f"Scan of {target}. {len(all_findings)} findings.",
            "technologies": spider_data.get("technologies_detected", []),
            "findings": all_findings,
            "statistics": {"pages_crawled": len(spider_data.get("pages", [])), "total_findings": len(all_findings)},
            "next_steps": ["Manual testing", "WPScan", "Auth testing"],
        }
    else:
        start = time.time()
        report = agent_coordinator(target, all_agent_results, duration)
        print(f"[+] Coordinator done in {time.time()-start:.1f}s")

    # ============================
    # Generate HTML report
    # ============================
    from report_generator import generate_report
    report_path = generate_report(report, target, duration)
    print(f"[+] HTML report: {report_path}")

    print(f"\n{'='*60}")
    print(f"[+] Scan completed in {int(duration//60)}m {int(duration%60)}s")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()

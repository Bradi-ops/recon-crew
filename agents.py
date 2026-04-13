# =============================================================================
# ReconCrew v3.1 - Agents with Real Agency
# =============================================================================
# Each agent has a decision loop:
#   1. PRE-SCAN:  LLM decides HOW to configure the tool (params, focus areas)
#   2. EXECUTE:   Tool runs with agent's chosen config
#   3. POST-SCAN: LLM analyzes results and decides if follow-up is needed
#   4. FOLLOW-UP: Optional second tool run (max 1 follow-up per agent)
#   5. REPORT:    LLM produces final analysis
#
# Decisions are bounded: LLM picks from predefined options, never free-form.
# If LLM fails at any decision point, a sensible default is used.
# =============================================================================

import json
from llm_client import llm_ask_json, llm_ask
from tools import web_spider, js_analyzer, secrets_scanner, form_analyzer, endpoint_prober


SYSTEM = """You are a penetration tester making tactical decisions during reconnaissance.
Respond with ONLY valid JSON. No markdown, no backticks, no explanation outside the JSON."""


# =============================================================================
# AGENT 1: Spider Agent
# =============================================================================
class SpiderAgent:
    """
    Decides crawl strategy, runs spider, then decides if additional
    targeted crawling is needed based on what was found.
    """

    def run(self, target_url: str) -> dict:
        print("    [Agent] Spider planning scan strategy...")

        # --- Decision 1: Plan crawl strategy ---
        plan = llm_ask_json(f"""Target: {target_url}
Based on the domain name, decide the crawl strategy.

Return JSON:
{{
  "max_depth": 2 or 3 or 4,
  "focus_areas": ["paths to prioritize, e.g. /api, /admin, /account"],
  "technology_guess": ["what tech you expect based on the domain"],
  "reasoning": "one line why"
}}""", SYSTEM)

        if plan:
            max_depth = min(plan.get("max_depth", 3), 5)
            print(f"    [Agent] Strategy: depth={max_depth}, expects {plan.get('technology_guess', ['unknown'])}")
        else:
            max_depth = 3
            print("    [Agent] Using default strategy (depth=3)")

        # --- Execute: Run spider ---
        print("    [Tool]  Crawling...")
        from config import MAX_CRAWL_DEPTH
        # Temporarily override depth if agent decided differently
        import config
        original_depth = config.MAX_CRAWL_DEPTH
        config.MAX_CRAWL_DEPTH = max_depth
        spider_data = web_spider(target_url)
        config.MAX_CRAWL_DEPTH = original_depth

        pages = len(spider_data.get("pages", []))
        js_count = len(spider_data.get("js_files", []))
        techs = spider_data.get("technologies_detected", [])
        print(f"    [Tool]  Found {pages} pages, {js_count} JS files, tech: {techs}")

        # --- Decision 2: Do we need a follow-up? ---
        followup = llm_ask_json(f"""Spider results summary:
- Pages: {pages}
- JS files: {js_count}
- Technologies: {json.dumps(techs)}
- Forms: {len(spider_data.get('forms', []))}
- Comments: {len(spider_data.get('comments', []))}
- Emails: {spider_data.get('emails', [])}
- Interesting headers: {json.dumps(spider_data.get('headers_of_interest', {{}}))}
- External links sample: {json.dumps(spider_data.get('external_links', [])[:5])}
- Meta generators: {json.dumps([m.get('content','') for m in spider_data.get('meta_tags',[]) if m.get('name')=='generator'])}

Based on these results, what additional sensitive paths should the secrets scanner check?
Think about what's relevant given the detected technologies.

Return JSON:
{{
  "additional_paths": ["/path1", "/path2"],
  "technology_specific_notes": "e.g. WordPress detected, check xmlrpc.php",
  "risk_assessment": "low|medium|high based on exposed surface",
  "findings": [
    {{"title": "...", "severity": "info|low|medium|high|critical", "category": "information_disclosure", "description": "...", "evidence": "...", "recommendation": "..."}}
  ]
}}""", SYSTEM)

        additional_paths = []
        analysis = {"findings": [], "technologies_summary": techs, "additional_paths": []}

        if followup:
            additional_paths = followup.get("additional_paths", [])
            analysis["findings"] = followup.get("findings", [])
            analysis["additional_paths"] = additional_paths
            analysis["risk_assessment"] = followup.get("risk_assessment", "unknown")
            analysis["technology_notes"] = followup.get("technology_specific_notes", "")
            print(f"    [Agent] Risk: {followup.get('risk_assessment','?')}, added {len(additional_paths)} extra paths")
        else:
            # Fallback findings
            for tech in techs:
                analysis["findings"].append({
                    "title": f"Technology: {tech}", "severity": "info",
                    "category": "information_disclosure", "description": f"Detected: {tech}",
                    "evidence": tech, "recommendation": "Keep components updated"
                })

        return {"tool_data": spider_data, "analysis": analysis, "extra_paths": additional_paths}


# =============================================================================
# AGENT 2: JS Agent
# =============================================================================
class JSAgent:
    """
    Decides which JS files are worth analyzing (skip CDN/libraries),
    runs analysis, then decides if any findings need deeper investigation.
    """

    def run(self, js_files: list, target_domain: str) -> dict:
        if not js_files:
            return {"tool_data": [], "analysis": {"findings": [], "notes": "No JS files"}}

        # --- Decision 1: Which JS files to analyze ---
        print(f"    [Agent] Evaluating {len(js_files)} JS files...")

        file_list_for_llm = js_files[:30]  # Cap for context
        decision = llm_ask_json(f"""Here are JavaScript files found on {target_domain}:
{json.dumps(file_list_for_llm, indent=2)}

Classify each as "analyze" or "skip". Skip CDN libraries (jquery, react, cloudflare, etc.)
and WordPress/WooCommerce core files. Analyze target-specific application JS.

Return JSON:
{{
  "analyze": ["url1", "url2"],
  "skip": ["url3"],
  "reasoning": "why these were selected"
}}""", SYSTEM)

        if decision and decision.get("analyze"):
            target_js = decision["analyze"]
            print(f"    [Agent] Selected {len(target_js)} files to analyze (skipped {len(js_files)-len(target_js)})")
        else:
            # Fallback: filter by common CDN patterns
            target_js = [f for f in js_files
                         if not any(s in f for s in ["jquery", "cloudflare", "cdn.", "googleapis",
                                                      "gstatic", "wp-includes", "wp-emoji",
                                                      "react.production", "react-dom.production"])]
            print(f"    [Agent] Auto-filtered to {len(target_js)} files (fallback)")

        if not target_js:
            return {"tool_data": [], "analysis": {"findings": [], "notes": "All JS are CDN/core"}}

        # --- Execute: Analyze selected JS ---
        print(f"    [Tool]  Analyzing {len(target_js)} JS files...")
        js_data = js_analyzer(target_js)

        total_ep = sum(len(f.get("endpoints", [])) for f in js_data if isinstance(f, dict))
        total_sec = sum(len(f.get("secrets", [])) for f in js_data if isinstance(f, dict))
        print(f"    [Tool]  Found {total_ep} endpoints, {total_sec} secrets")

        # --- Decision 2: Analyze results and flag high-priority items ---
        condensed = []
        for f in js_data:
            if isinstance(f, dict) and (f.get("endpoints") or f.get("secrets") or f.get("comments")):
                condensed.append({
                    "file": f.get("file", ""), "endpoints": f.get("endpoints", [])[:15],
                    "secrets": f.get("secrets", []), "comments": f.get("comments", [])[:5],
                    "source_maps": f.get("source_maps", []),
                })

        analysis = {"findings": [], "interesting_endpoints": [], "notes": ""}

        if condensed:
            result = llm_ask_json(f"""Analyze these JS findings for security impact:
{json.dumps(condensed, indent=2)}

Return JSON:
{{
  "findings": [{{"title":"...", "severity":"critical|high|medium|low|info", "category":"endpoints|secrets|information_disclosure", "description":"...", "evidence":"...", "recommendation":"..."}}],
  "interesting_endpoints": ["endpoints worth manual testing"],
  "notes": "architecture observations"
}}""", SYSTEM)

            if result:
                analysis = result
                print(f"    [Agent] Identified {len(result.get('findings', []))} security findings")
            else:
                # Fallback
                for f in js_data:
                    if isinstance(f, dict):
                        for s in f.get("secrets", []):
                            analysis["findings"].append({
                                "title": f"Secret in JS: {s['type']}", "severity": "high",
                                "category": "secrets", "description": f"Found in {f.get('file','?')}",
                                "evidence": s["value"][:50], "recommendation": "Remove from client-side code"
                            })

        return {"tool_data": js_data, "analysis": analysis}


# =============================================================================
# AGENT 3: Secrets Agent
# =============================================================================
class SecretsAgent:
    """
    Takes base paths + any extra paths from Spider Agent,
    runs secrets scan, then decides if discovered files need deeper probing.
    """

    def run(self, target_url: str, extra_paths: list = None) -> dict:
        # --- Execute: Run secrets scanner (it has its own path list) ---
        print("    [Tool]  Scanning sensitive paths...")
        secrets_data = secrets_scanner(target_url)

        # If spider agent suggested extra paths, scan those too
        if extra_paths:
            print(f"    [Agent] Also checking {len(extra_paths)} paths from Spider agent...")
            import httpx
            from config import USER_AGENT, REQUEST_TIMEOUT, REQUEST_DELAY, SECRET_PATTERNS
            import time, re
            client = httpx.Client(headers={"User-Agent": USER_AGENT},
                                  timeout=REQUEST_TIMEOUT, follow_redirects=True, verify=False)
            base = target_url.rstrip("/")
            for path in extra_paths[:20]:
                time.sleep(REQUEST_DELAY)
                try:
                    url = f"{base}{path}" if not path.startswith("http") else path
                    r = client.get(url)
                    if r.status_code == 200 and len(r.text) > 50 and "not found" not in r.text.lower()[:200]:
                        finding = {"path": path, "url": url, "status": 200,
                                   "size": len(r.text), "content_type": r.headers.get("content-type", ""),
                                   "secrets_found": [], "preview": r.text[:300], "source": "spider_agent"}
                        for name, pat in SECRET_PATTERNS.items():
                            for m in re.findall(pat, r.text):
                                val = m if isinstance(m, str) else m[0]
                                finding["secrets_found"].append({"type": name, "value": val[:60]})
                        secrets_data.append(finding)
                    elif r.status_code == 403:
                        secrets_data.append({"path": path, "url": url, "status": 403,
                                             "note": "Forbidden", "source": "spider_agent"})
                except Exception:
                    continue
            client.close()

        accessible = len([s for s in secrets_data if s.get("status") == 200])
        forbidden = len([s for s in secrets_data if s.get("status") == 403])
        print(f"    [Tool]  Accessible: {accessible}, Forbidden: {forbidden}")

        # --- Decision: Analyze what was found ---
        if not secrets_data:
            return {"tool_data": [], "analysis": {"findings": [], "notes": "No sensitive paths found"}}

        result = llm_ask_json(f"""Analyze these sensitive path scan results:
{json.dumps(secrets_data, indent=2)}

Return JSON:
{{
  "findings": [{{"title":"...", "severity":"critical|high|medium|low|info", "category":"secrets|misconfig", "description":"...", "evidence":"...", "recommendation":"..."}}],
  "notes": "overall assessment"
}}""", SYSTEM)

        analysis = {"findings": [], "notes": ""}
        if result:
            analysis = result
            print(f"    [Agent] {len(result.get('findings', []))} findings from secrets analysis")
        else:
            for s in secrets_data:
                sev = "high" if s.get("secrets_found") else ("medium" if s.get("status") == 200 else "low")
                analysis["findings"].append({
                    "title": f"Sensitive Path: {s.get('path','?')}", "severity": sev,
                    "category": "secrets", "description": f"HTTP {s.get('status')} on {s.get('path')}",
                    "evidence": s.get("preview", "")[:200], "recommendation": "Restrict access"
                })

        return {"tool_data": secrets_data, "analysis": analysis}


# =============================================================================
# AGENT 4: Forms Agent
# =============================================================================
class FormsAgent:
    """Analyzes forms and decides which ones are worth flagging."""

    def run(self, forms: list) -> dict:
        if not forms:
            return {"tool_data": [], "analysis": {"findings": [], "notes": "No forms"}}

        print(f"    [Tool]  Analyzing {len(forms)} forms...")
        forms_data = form_analyzer(forms)
        print(f"    [Tool]  {len(forms_data)} forms with issues")

        if not forms_data:
            return {"tool_data": [], "analysis": {"findings": [], "notes": "No form issues"}}

        # Summarize for LLM
        summary = {"total": len(forms_data), "issue_types": {}, "samples": forms_data[:8]}
        for f in forms_data:
            for finding in f.get("findings", []):
                t = finding.get("type", "?")
                summary["issue_types"][t] = summary["issue_types"].get(t, 0) + 1

        result = llm_ask_json(f"""Analyze form security findings:
{json.dumps(summary, indent=2)}

Return JSON:
{{
  "findings": [{{"title":"...", "severity":"critical|high|medium|low|info", "category":"forms", "description":"...", "evidence":"...", "recommendation":"..."}}],
  "notes": "overall form security"
}}""", SYSTEM)

        analysis = {"findings": [], "notes": ""}
        if result:
            analysis = result
            print(f"    [Agent] {len(result.get('findings', []))} form findings")
        else:
            for ftype, count in summary["issue_types"].items():
                analysis["findings"].append({
                    "title": f"{ftype} ({count} forms)", "severity": "medium",
                    "category": "forms", "description": f"{count} forms affected",
                    "evidence": f"Across {count} forms", "recommendation": "Review form security"
                })

        return {"tool_data": forms_data, "analysis": analysis}


# =============================================================================
# AGENT 5: Endpoint Prober
# =============================================================================
class ProberAgent:
    """
    Decides which endpoints to probe based on prior findings,
    runs async prober, then decides if any results need deeper probing.
    """

    def run(self, target_url: str, js_endpoints: list, technologies: list) -> dict:
        # --- Decision 1: What to probe ---
        print("    [Agent] Planning probe strategy...")

        probe_plan = llm_ask_json(f"""Target: {target_url}
Technologies detected: {json.dumps(technologies)}
Endpoints from JS analysis: {json.dumps(js_endpoints[:30])}

Decide what additional endpoints to probe beyond those already found.
Consider the detected technologies (e.g., WordPress → wp-json, xmlrpc).

Return JSON:
{{
  "additional_endpoints": ["/path1", "/path2"],
  "priority_methods": ["GET", "POST", "PUT", "DELETE"],
  "reasoning": "why these endpoints matter"
}}""", SYSTEM)

        all_endpoints = set(js_endpoints)

        if probe_plan:
            extra = probe_plan.get("additional_endpoints", [])
            all_endpoints.update(extra)
            print(f"    [Agent] Added {len(extra)} tech-specific endpoints to probe")
        else:
            # Fallback: WP defaults
            wp = ["/wp-json/wp/v2/users", "/wp-json/", "/wp-admin/", "/wp-login.php",
                  "/wp-content/debug.log", "/xmlrpc.php", "/?rest_route=/wp/v2/users"]
            all_endpoints.update(wp)
            print(f"    [Agent] Using default WP endpoints (fallback)")

        all_endpoints.discard("")

        # --- Execute: Probe ---
        print(f"    [Tool]  Probing {len(all_endpoints)} endpoints (async)...")
        probe_data = endpoint_prober(target_url.rstrip("/"), list(all_endpoints))

        by_status = {}
        for r in probe_data:
            s = r.get("status", "?")
            by_status[s] = by_status.get(s, 0) + 1
        print(f"    [Tool]  {len(probe_data)} interesting responses: {dict(sorted(by_status.items()))}")

        # --- Decision 2: Which results are security-relevant ---
        notable = []
        for r in probe_data:
            if (r.get("method") in ("PUT", "DELETE", "PATCH") and r.get("status") == 200) or \
               r.get("status") in (401, 403, 500, 422) or \
               any(kw in r.get("endpoint", "") for kw in ["admin", "debug", "config", "users", "upload"]):
                notable.append(r)

        probe_summary = {
            "total_responses": len(probe_data),
            "by_status": by_status,
            "notable_responses": notable[:25],
        }

        result = llm_ask_json(f"""Analyze probing results for access control and security issues:
{json.dumps(probe_summary, indent=2)}

Return JSON:
{{
  "findings": [{{"title":"...", "severity":"critical|high|medium|low|info", "category":"endpoints|misconfig", "description":"...", "evidence":"...", "recommendation":"..."}}],
  "notes": "access control assessment"
}}""", SYSTEM)

        analysis = {"findings": [], "notes": ""}
        if result:
            analysis = result
            print(f"    [Agent] {len(result.get('findings', []))} probe findings")
        else:
            for r in notable[:10]:
                analysis["findings"].append({
                    "title": f"{r.get('method')} {r.get('endpoint','?')} → {r.get('status')}",
                    "severity": "medium", "category": "endpoints",
                    "description": f"Endpoint responds to {r.get('method')} with {r.get('status')}",
                    "evidence": json.dumps(r), "recommendation": "Review access controls"
                })

        return {"tool_data": probe_data, "analysis": analysis}


# =============================================================================
# AGENT 6: Coordinator
# =============================================================================
class CoordinatorAgent:
    """Synthesizes all agent findings into final report."""

    def run(self, target: str, all_results: dict, duration: float) -> dict:
        all_findings = []
        all_techs = []
        notes = []

        for name, result in all_results.items():
            analysis = result.get("analysis", {})
            all_findings.extend(analysis.get("findings", []))
            all_techs.extend(analysis.get("technologies_summary", []))
            n = analysis.get("notes") or analysis.get("attack_surface_notes") or analysis.get("technology_notes")
            if n:
                notes.append(f"{name}: {n}")

        all_techs = list(set(all_techs))

        summary = {
            "target": target, "total_findings": len(all_findings),
            "by_severity": {}, "agent_notes": notes,
            "technologies": all_techs, "findings": all_findings[:60],
        }
        for f in all_findings:
            s = f.get("severity", "info")
            summary["by_severity"][s] = summary["by_severity"].get(s, 0) + 1

        result = llm_ask_json(f"""Synthesize all findings into a final pentest recon report.

DATA:
{json.dumps(summary, indent=2)}

Return JSON:
{{
  "executive_summary": "2-3 paragraphs: scope, key risks, security posture",
  "technologies": ["final tech list"],
  "findings": [sorted by severity, each with title/severity/category/description/evidence/recommendation],
  "statistics": {{"pages_crawled": 0, "total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}},
  "next_steps": ["prioritized manual testing recommendations"]
}}""", SYSTEM)

        if result:
            print(f"    [Agent] Report: {len(result.get('findings',[]))} findings")
            return result

        # Fallback
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        all_findings.sort(key=lambda f: sev_order.get(f.get("severity", "info"), 5))
        stats = {"total_findings": len(all_findings)}
        for f in all_findings:
            s = f.get("severity", "info")
            stats[s] = stats.get(s, 0) + 1

        return {
            "executive_summary": f"Recon scan of {target}. {len(all_findings)} findings identified.",
            "technologies": all_techs, "findings": all_findings,
            "statistics": stats,
            "next_steps": ["Manual testing of critical findings", "Auth testing", "SQLi testing", "WPScan"],
        }
